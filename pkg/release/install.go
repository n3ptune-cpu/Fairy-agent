package release

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Installer replaces a program's binary with a verified new one, starts it and checks it is healthy; if not,
// it puts the previous binary back and starts that again. The previous binary stays next to it as
// "<name>.old" (Windows: "<name>.exe.old").
type Installer struct {
	Target string // the installed binary, e.g. /usr/local/bin/fairy-agent

	// Stop runs before the swap (Windows: stop the service, so the new exe can take the name); may be nil.
	Stop func(ctx context.Context) error
	// Start runs after the swap and again after a rollback (Linux: systemctl restart <unit>).
	Start func(ctx context.Context) error
	// Healthy is asked once a second until it has said yes HealthPasses times in a row, or HealthTimeout ends.
	Healthy func(ctx context.Context) error
	// HealthyPrevious is asked instead of Healthy after a rollback, when the PREVIOUS version runs again: a
	// check that expects the new version (Healthy) can never pass then. nil: Healthy is asked.
	HealthyPrevious func(ctx context.Context) error
	HealthTimeout   time.Duration // default 30 s
	HealthPasses    int           // default 1
	Interval        time.Duration // default 1 s
	// Relabel runs after the new binary is in place (restorecon on SELinux hosts); may be nil.
	Relabel func(path string)
	// RenameSwap moves the old binary aside before moving the new one in (needed on Windows, where a running
	// exe cannot be replaced, only renamed). The default keeps a hard link as .old and renames over the target,
	// so the target name never disappears.
	RenameSwap bool
	Logf       func(format string, args ...any)
}

// RolledBackError says the new binary did not come up and the previous one was put back.
type RolledBackError struct {
	Cause       error
	RollbackErr error // nil when the previous version is running again
}

func (e *RolledBackError) Error() string {
	if e.RollbackErr != nil {
		return fmt.Sprintf("%v; rolling back FAILED too: %v", e.Cause, e.RollbackErr)
	}
	return fmt.Sprintf("%v; rolled back to the previous version", e.Cause)
}

func (e *RolledBackError) Unwrap() error { return e.Cause }

func (in *Installer) logf(format string, args ...any) {
	if in.Logf != nil {
		in.Logf(format, args...)
	}
}

// OldPath is where the previous binary is kept.
func (in *Installer) OldPath() string { return in.Target + ".old" }

// Install swaps newPath (a verified binary in the same folder as Target) into place. newPath is consumed.
func (in *Installer) Install(ctx context.Context, newPath string) (err error) {
	if filepath.Dir(filepath.Clean(newPath)) != filepath.Dir(filepath.Clean(in.Target)) {
		os.Remove(newPath)
		return errors.New("the new binary must be in the same folder as the installed one")
	}
	defer func() {
		if err != nil {
			os.Remove(newPath) // no-op once it has been renamed into place
		}
	}()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(newPath, 0o755); err != nil {
			return err
		}
	}
	if in.Stop != nil {
		if err := in.Stop(ctx); err != nil {
			return fmt.Errorf("stopping the running version: %w", err)
		}
	}
	old := in.OldPath()
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		in.restart(ctx)
		return fmt.Errorf("removing the previous backup %s: %w", old, err)
	}
	if in.RenameSwap {
		if err := os.Rename(in.Target, old); err != nil {
			in.restart(ctx)
			return fmt.Errorf("moving the running version aside: %w", err)
		}
		if err := os.Rename(newPath, in.Target); err != nil {
			_ = os.Rename(old, in.Target)
			in.restart(ctx)
			return fmt.Errorf("putting the new version in place: %w", err)
		}
	} else {
		if err := linkOrCopy(in.Target, old); err != nil {
			in.restart(ctx)
			return fmt.Errorf("keeping a copy of the running version: %w", err)
		}
		if err := os.Rename(newPath, in.Target); err != nil {
			in.restart(ctx)
			return fmt.Errorf("putting the new version in place: %w", err)
		}
	}
	in.logf("new binary in place at %s (previous one kept as %s)", in.Target, old)
	if in.Relabel != nil {
		in.Relabel(in.Target)
	}
	if err := in.Start(ctx); err != nil {
		return in.rollback(ctx, fmt.Errorf("starting the new version: %w", err))
	}
	if err := in.waitHealthy(ctx); err != nil {
		return in.rollback(ctx, fmt.Errorf("the new version did not become healthy: %w", err))
	}
	return nil
}

// restart starts the unchanged old version again after a failed swap (best effort).
func (in *Installer) restart(ctx context.Context) {
	if in.Stop != nil {
		if err := in.Start(ctx); err != nil {
			in.logf("starting the previous version again failed: %v", err)
		}
	}
}

func (in *Installer) rollback(ctx context.Context, cause error) error {
	in.logf("%v; rolling back", cause)
	ctx = context.WithoutCancel(ctx)
	if in.Stop != nil {
		if err := in.Stop(ctx); err != nil {
			in.logf("stopping the new version failed: %v", err)
		}
	}
	old := in.OldPath()
	if in.RenameSwap {
		failed := in.Target + ".failed"
		_ = os.Remove(failed)
		if err := os.Rename(in.Target, failed); err != nil {
			return &RolledBackError{Cause: cause, RollbackErr: err}
		}
	}
	if err := os.Rename(old, in.Target); err != nil {
		return &RolledBackError{Cause: cause, RollbackErr: err}
	}
	if in.Relabel != nil {
		in.Relabel(in.Target)
	}
	if err := in.Start(ctx); err != nil {
		return &RolledBackError{Cause: cause, RollbackErr: fmt.Errorf("starting the previous version: %w", err)}
	}
	check := in.HealthyPrevious
	if check == nil {
		check = in.Healthy
	}
	if err := in.waitFor(ctx, check); err != nil {
		return &RolledBackError{Cause: cause, RollbackErr: fmt.Errorf("the previous version is not healthy either: %w", err)}
	}
	in.logf("previous version restored and healthy")
	return &RolledBackError{Cause: cause}
}

func (in *Installer) waitHealthy(ctx context.Context) error { return in.waitFor(ctx, in.Healthy) }

// waitFor asks healthy once every Interval until it has said yes HealthPasses times in a row.
func (in *Installer) waitFor(ctx context.Context, healthy func(context.Context) error) error {
	timeout, passes, every := in.HealthTimeout, in.HealthPasses, in.Interval
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if passes <= 0 {
		passes = 1
	}
	if every <= 0 {
		every = time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var last error
	ok := 0
	for {
		if err := healthy(ctx); err != nil {
			last, ok = err, 0
		} else if ok++; ok >= passes {
			return nil
		}
		select {
		case <-ctx.Done():
			if last == nil {
				last = errors.New("not healthy long enough")
			}
			return fmt.Errorf("after %s: %w", timeout, last)
		case <-time.After(every):
		}
	}
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

// ReadStaged reads a small staged file that a less privileged process wrote: no symlinks, regular files only,
// at most max bytes. The caller verifies the content (it is untrusted).
func ReadStaged(path string, max int64) ([]byte, error) {
	f, err := openStaged(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	return b, nil
}

func openStaged(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	if st2, err := f.Stat(); err != nil || !os.SameFile(st, st2) {
		f.Close()
		return nil, fmt.Errorf("%s changed while it was opened", path)
	}
	return f, nil
}

// CopyVerified copies a staged binary into dir (a new file with a random name, e.g. next to the installed
// binary), hashing exactly the bytes it writes, and keeps it only if they match want. Checking the copy (not the
// staged file) means a change to the staged file after the check cannot slip through.
func CopyVerified(src, dir string, want [32]byte) (string, error) {
	in, err := openStaged(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp(dir, "."+filepath.Base(src)+".new-*")
	if err != nil {
		return "", err
	}
	path := out.Name()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, MaxAssetSize+1))
	if err == nil && n > MaxAssetSize {
		err = errors.New("the staged binary is too large")
	}
	if err == nil && [32]byte(h.Sum(nil)) != want {
		err = errors.New("the staged binary does not match the signed " + SumsFile)
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}
