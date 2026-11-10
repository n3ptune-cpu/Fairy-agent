package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// Self-update, in two halves:
//
//  1. The agent (POST /update, control token, self_update.enabled): checks the latest Fairy-agent release on
//     GitHub, verifies its signature with the key built into this binary, downloads its own platform's binary and
//     stages it with the signed files in a folder it may write (Linux: /var/lib/fairy-agent/update; Windows:
//     C:\ProgramData\fairy-agent\update\stage). Then it starts the installer: Linux the root unit
//     fairy-agent-update.service (allowed by the polkit rule), Windows the LocalSystem service
//     fairy-agent-update (the agent's service account may only start it). The agent itself can never write the
//     installed program: only the installer, which runs the installed (administrator-owned) binary, can.
//  2. The installer (`fairy-agent apply-update`, ApplyUpdate): verifies everything AGAIN with its own built-in
//     key (it never trusts the stage, and refuses links / junctions in it), copies the binary next to the
//     installed one while hashing exactly the copied bytes, swaps it in (keeping fairy-agent.old), restarts the
//     service and waits until the agent proves that it runs the new version (GET /health, see health.go: the
//     token is never sent); otherwise it puts the old binary back and restarts that. The result goes to a file only the installer may write, which the agent reads (and
//     reports in /metrics as self_update.last).

// UpdateStatus is the /metrics "self_update" block.
type UpdateStatus struct {
	State   string        `json:"state"` // idle | downloading | applying | failed | unavailable
	Message string        `json:"message,omitempty"`
	Target  string        `json:"target,omitempty"` // the version being installed
	Since   float64       `json:"since"`
	Last    *UpdateResult `json:"last,omitempty"` // the installer's last result
}

// UpdateResult is what the installer writes when it is done.
type UpdateResult struct {
	ID      string  `json:"id"`
	OK      bool    `json:"ok"`
	From    string  `json:"from"`
	To      string  `json:"to"`
	Message string  `json:"message"`
	At      float64 `json:"at"`
}

// UpdateRequest is the POST /update body.
type UpdateRequest struct {
	// Force is read and ignored: a request from the network never reinstalls the same version or installs an
	// older one (the panel never sent it). That is for root / an administrator on the machine:
	// fairy-agent update --force.
	Force       bool `json:"force"`
	RequestedBy any  `json:"requested_by"`
}

// UpdateCooldown is the least time between two installer runs that were asked for through the agent (the
// panel's Update button). A run restarts the agent (on Windows the helper too, so the fans go back to the BMC
// for a moment); without a pause, whoever holds the control token could keep a machine restarting. The
// installer keeps the time itself, where the agent's account cannot write. `fairy-agent update` on the
// machine is not held back by it.
const UpdateCooldown = 10 * time.Minute

// lastApplyFile, next to the installer's result file, holds the time (Unix seconds) of the installer's last
// run that went as far as replacing the program.
const lastApplyFile = "last-apply"

func lastApplyPath(resultPath string) string {
	return filepath.Join(filepath.Dir(resultPath), lastApplyFile)
}

// cooldownLeft is how long the installer still refuses a new run (0: it does not). A missing or unreadable
// time, or one in the future (the clock was set back), holds nothing back.
func cooldownLeft(resultPath string, now time.Time) time.Duration {
	if resultPath == "" {
		return 0
	}
	b, err := release.ReadStaged(lastApplyPath(resultPath), 64)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	age := now.Sub(time.Unix(n, 0))
	if age < 0 || age >= UpdateCooldown {
		return 0
	}
	return UpdateCooldown - age
}

func cooldownMessage(left time.Duration) string {
	return fmt.Sprintf("an update was installed on this machine less than %d minutes ago; refused, try again in %s "+
		"(on the machine itself, any time: fairy-agent update)", int(UpdateCooldown/time.Minute), left.Round(time.Second))
}

// stageRequest is request.json in the stage folder.
type stageRequest struct {
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
	// Force is no longer written, and the installer ignores it: the stage belongs to the less privileged
	// agent, so nothing in it can ask for the same or an older version.
	Force       bool    `json:"force,omitempty"`
	RequestedBy string  `json:"requested_by"`
	At          float64 `json:"at"`
}

const stageRequestFile = "request.json"

// UpdaterOptions build an Updater (DefaultUpdaterOptions has the real ones).
type UpdaterOptions struct {
	Version    string            // this binary's version
	Key        ed25519.PublicKey // nil: unavailable (local build)
	KeyErr     error             // why Key is nil
	Client     *release.Client
	StageDir   string
	ResultPath string
	Asset      string                          // this platform's release file
	Apply      func(ctx context.Context) error // start the installer
	ResultWait time.Duration                   // how long to wait for the installer's result (default 5 min)
	// Ready says why the installer cannot be started on this machine (nil: it can), e.g. Windows without the
	// fairy-agent-update service. Asked at start, before each update and (while it fails) once a minute.
	Ready func() error
}

// Updater runs POST /update.
type Updater struct {
	o   UpdaterOptions
	now func() time.Time

	mu        sync.Mutex
	st        UpdateStatus
	busy      bool
	done      chan struct{} // closed when a run ends (tests)
	resultMod time.Time     // the result file's mtime when it was last read
	checkedAt time.Time
	notReady  bool      // unavailable because o.Ready failed
	readyAt   time.Time // when o.Ready was last asked
}

// NewUpdater returns the updater and reads the installer's last result.
func NewUpdater(o UpdaterOptions) *Updater {
	if o.ResultWait == 0 {
		o.ResultWait = 5 * time.Minute
	}
	u := &Updater{o: o, now: time.Now}
	u.st = UpdateStatus{State: "idle", Since: u.ts()}
	if len(o.Key) == 0 {
		u.st.State, u.st.Message = "unavailable", release.ErrNoKey.Error()
		if o.KeyErr != nil && !errors.Is(o.KeyErr, release.ErrNoKey) {
			u.st.Message = o.KeyErr.Error()
		}
	} else {
		u.checkReady()
	}
	u.refreshLast(true)
	return u
}

// checkReady asks o.Ready and makes the state unavailable (or idle again). Caller holds u.mu (or owns u).
func (u *Updater) checkReady() bool {
	if u.o.Ready == nil || len(u.o.Key) == 0 {
		return true
	}
	u.readyAt = time.Now()
	if err := u.o.Ready(); err != nil {
		if !u.busy {
			u.st.State, u.st.Message, u.st.Since = "unavailable", err.Error(), u.ts()
		}
		u.notReady = true
		return false
	}
	if u.notReady && !u.busy {
		u.st.State, u.st.Message, u.st.Since = "idle", "", u.ts()
	}
	u.notReady = false
	return true
}

// refreshLast picks up a new result file. The installer writes it only after the restarted agent has proven
// healthy (or after the rollback), i.e. while this process is already running. Caller holds u.mu (or owns u).
func (u *Updater) refreshLast(force bool) {
	if u.o.ResultPath == "" || (!force && time.Since(u.checkedAt) < 2*time.Second) {
		return
	}
	u.checkedAt = time.Now()
	st, err := os.Stat(u.o.ResultPath)
	if err != nil || st.ModTime().Equal(u.resultMod) {
		return
	}
	u.resultMod = st.ModTime()
	r := readResult(u.o.ResultPath)
	if r == nil {
		return
	}
	u.st.Last = r
	if u.busy {
		return
	}
	switch {
	case !r.OK && u.ts()-r.At < 3600 && u.st.State == "idle":
		u.st.State, u.st.Message = "failed", r.Message
	case r.OK && u.st.State == "failed" && !force:
		u.st.State, u.st.Message = "idle", r.Message
	}
}

func (u *Updater) ts() float64 { return collect.Round(float64(u.now().UnixMilli())/1000, 3) }

// Status is the current state.
func (u *Updater) Status() UpdateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.notReady && time.Since(u.readyAt) > time.Minute {
		u.checkReady() // e.g. setup-self-update was run since
	}
	u.refreshLast(false)
	st := u.st
	if st.Last != nil {
		l := *st.Last
		st.Last = &l
	}
	return st
}

func (u *Updater) set(state, msg, target string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.st.State, u.st.Message, u.st.Target, u.st.Since = state, msg, target, u.ts()
}

// Start handles POST /update: it answers at once (202) and works in the background; /metrics shows progress.
func (u *Updater) Start(req UpdateRequest) (int, map[string]any) {
	who := cleanWho(req.RequestedBy)
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.o.Key) == 0 {
		return 503, map[string]any{"error": u.st.Message, "code": "self_update_unavailable"}
	}
	if u.busy {
		return 409, map[string]any{"error": "an update is already in progress (" + u.st.State + ")", "state": u.st.State}
	}
	if !u.checkReady() {
		return 503, map[string]any{"error": u.st.Message, "code": "self_update_unavailable"}
	}
	u.busy = true
	u.done = make(chan struct{})
	u.st.State, u.st.Message, u.st.Target, u.st.Since = "downloading", "checking the latest release", "", u.ts()
	slog.Warn("self-update: requested", "requested_by", who, "current", u.o.Version)
	if req.Force {
		slog.Warn("self-update: \"force\" in the request is ignored (the same or an older version is only installed by hand: fairy-agent update --force)",
			"requested_by", who)
	}
	go u.run(who, u.done)
	return 202, map[string]any{"state": "downloading", "current": u.o.Version}
}

func (u *Updater) finish(done chan struct{}) {
	u.mu.Lock()
	u.busy = false
	u.mu.Unlock()
	close(done)
}

func (u *Updater) fail(msg, target string) {
	slog.Error("self-update failed", "error", msg, "target", target)
	u.set("failed", msg, target)
}

func (u *Updater) run(who string, done chan struct{}) {
	defer u.finish(done)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	ch, err := u.o.Client.Check(ctx, u.o.Key, release.AgentProgram)
	if err != nil {
		u.fail("checking the latest release: "+safeErr(err), "")
		return
	}
	cmp, known := release.Compare(u.o.Version, ch.Version)
	switch {
	case cmp == 0:
		slog.Info("self-update: already up to date", "version", u.o.Version)
		u.set("idle", "already up to date ("+u.o.Version+")", "")
		return
	case cmp < 0:
		u.fail(fmt.Sprintf("the latest release %s is older than this agent (%s); not downgrading", ch.Version, u.o.Version), ch.Version)
		return
	case !known && release.NoBuildNumber(ch.Version) != "":
		// A release in another version format: the installer refuses it (applyStaged), so say so here, before
		// anything is downloaded.
		u.fail(release.NotComparable(u.o.Version, ch.Version).Error()+"; not installing (by hand, as root / Administrator: fairy-agent update --force)", ch.Version)
		return
	case !known:
		// This agent's own version has no build number (a local build). The agent is the less privileged side
		// and not the one that decides: it stages the release and the installer, whose word counts, refuses.
		slog.Warn("self-update: this agent's version has no build number (a local build?); the installer will refuse to replace it",
			"current", u.o.Version, "release", ch.Version)
	}
	// The installer would refuse (applyStaged): say so before anything is downloaded.
	if left := cooldownLeft(u.o.ResultPath, u.now()); left > 0 {
		u.fail(cooldownMessage(left), ch.Version)
		return
	}
	u.set("downloading", "downloading "+ch.Version+" ("+ch.Tag+")", ch.Version)
	slog.Info("self-update: downloading", "release", ch.Tag, "version", ch.Version, "asset", u.o.Asset)
	id, err := u.stage(ctx, ch, who)
	if err != nil {
		u.fail(safeErr(err), ch.Version)
		return
	}
	u.set("applying", "installing "+ch.Version+"; the agent restarts", ch.Version)
	slog.Warn("self-update: starting the installer", "version", ch.Version, "id", id)
	if err := u.o.Apply(ctx); err != nil {
		u.fail("starting the installer: "+safeErr(err), ch.Version)
		return
	}
	// Normally the installer restarts this process. If we are still here, wait for its verdict.
	deadline := time.Now().Add(u.o.ResultWait)
	for time.Now().Before(deadline) {
		if r := readResult(u.o.ResultPath); r != nil && r.ID == id {
			u.mu.Lock()
			u.st.Last = r
			u.mu.Unlock()
			if r.OK {
				u.set("idle", r.Message, "")
			} else {
				u.fail(r.Message, ch.Version)
			}
			return
		}
		time.Sleep(time.Second)
	}
	u.fail("the installer did not report back (Linux: journalctl -u fairy-agent-update; Windows: the agent log)", ch.Version)
}

// stage writes the verified release files and the binary into the stage folder.
func (u *Updater) stage(ctx context.Context, ch *release.Checked, who string) (string, error) {
	dir := u.o.StageDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("stage folder %s: %w%s", dir, err, stageHint)
	}
	if err := clearDir(dir); err != nil {
		return "", err
	}
	tmp, err := u.o.Client.FetchAsset(ctx, ch, u.o.Asset, dir)
	if err != nil {
		return "", err
	}
	if err := os.Rename(tmp, filepath.Join(dir, u.o.Asset)); err != nil {
		os.Remove(tmp)
		return "", err
	}
	idb := make([]byte, 8)
	_, _ = rand.Read(idb)
	id := hex.EncodeToString(idb)
	req, _ := json.Marshal(stageRequest{ID: id, From: u.o.Version, To: ch.Version, RequestedBy: who, At: u.ts()})
	for name, data := range map[string][]byte{release.SumsFile: ch.SumsRaw, release.SigFile: ch.SigRaw,
		release.VersionFile: ch.VersionRaw, stageRequestFile: req} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return "", err
		}
	}
	return id, nil
}

func clearDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func readResult(path string) *UpdateResult {
	if path == "" {
		return nil
	}
	b, err := release.ReadStaged(path, 16<<10)
	if err != nil {
		return nil
	}
	var r UpdateResult
	if json.Unmarshal(b, &r) != nil || r.ID == "" {
		return nil
	}
	return &r
}

// ---- the installer side

// ApplyOptions are the installer's inputs (ApplyUpdate has the real ones).
type ApplyOptions struct {
	StageDir, ResultPath string
	Asset                string
	Key                  ed25519.PublicKey
	CurrentVersion       string             // the installed (and running) version
	Installer            *release.Installer // Target, Stop, Start, Relabel, RenameSwap; Healthy is set here
	Healthy              func(ctx context.Context, version string) error
	Now                  func() time.Time // nil: time.Now (the cooldown; tests)
}

var idRe = regexp.MustCompile(`^[0-9a-f]{1,32}$`)

// ApplyStaged verifies the staged release with its own key, installs it and writes the result file.
func ApplyStaged(ctx context.Context, o ApplyOptions) UpdateResult {
	res := UpdateResult{ID: "unknown", From: o.CurrentVersion, At: float64(time.Now().Unix())}
	err := applyStaged(ctx, o, &res)
	res.At = float64(time.Now().Unix())
	if err != nil {
		res.OK, res.Message = false, "update to "+orUnknown(res.To)+" failed: "+err.Error()
		slog.Error("apply-update failed", "from", res.From, "to", res.To, "error", err.Error())
	} else {
		res.OK, res.Message = true, "updated from "+res.From+" to "+res.To
		slog.Warn("apply-update: done", "from", res.From, "to", res.To)
	}
	if werr := writeResult(o.ResultPath, res); werr != nil {
		slog.Error("apply-update: cannot write the result file", "path", o.ResultPath, "error", werr.Error())
	}
	return res
}

func orUnknown(s string) string {
	if s == "" {
		return "the new version"
	}
	return s
}

func applyStaged(ctx context.Context, o ApplyOptions, res *UpdateResult) error {
	if err := realDir(o.StageDir); err != nil {
		return err
	}
	unlock, err := lockDir(o.StageDir) // Windows: it cannot be removed or turned into a junction while we read
	if err != nil {
		return fmt.Errorf("stage folder: %w", err)
	}
	defer unlock()
	if err := plainIfExists(filepath.Dir(o.ResultPath)); err != nil {
		return fmt.Errorf("result folder: %w", err)
	}
	p := func(n string) string { return filepath.Join(o.StageDir, n) }
	var req stageRequest
	if b, err := release.ReadStaged(p(stageRequestFile), 4<<10); err != nil {
		return fmt.Errorf("nothing staged: %w", err)
	} else if json.Unmarshal(b, &req) != nil {
		return errors.New("stage: unreadable request.json")
	}
	if idRe.MatchString(req.ID) {
		res.ID = req.ID
	}
	var files [3][]byte
	for i, n := range []string{release.SumsFile, release.SigFile, release.VersionFile} {
		b, err := release.ReadStaged(p(n), 64<<10)
		if err != nil {
			return fmt.Errorf("stage: %w", err)
		}
		files[i] = b
	}
	ch, err := release.VerifyFiles(o.Key, release.AgentProgram, files[0], files[1], files[2])
	if err != nil {
		return err
	}
	res.To = ch.Version
	cmp, known := release.Compare(o.CurrentVersion, ch.Version)
	slog.Warn("apply-update: verified the staged release", "from", o.CurrentVersion, "to", ch.Version,
		"requested_by", cleanWho(req.RequestedBy))
	// The stage is written by the less privileged agent: nothing in it (request.json's "force") makes the
	// installer put the same version in again, which only restarts the service, or an older one, which may
	// have flaws fixed since. Both are for root / an administrator: fairy-agent update --force.
	if cmp == 0 {
		return errors.New("already installed (to install it again, by hand: fairy-agent update --force)")
	}
	if known && cmp < 0 {
		return fmt.Errorf("%s is older than the installed %s; not downgrading (by hand: fairy-agent update --force)", ch.Version, o.CurrentVersion)
	}
	// "Never older" can only be told from build numbers. A signed release in another format (v0.4.2), or with a
	// build number too long to read, is not "newer": refused here too, force or not.
	if !known {
		return fmt.Errorf("%w; not installing (by hand: fairy-agent update --force)", release.NotComparable(o.CurrentVersion, ch.Version))
	}
	want, ok := ch.Sums[o.Asset]
	if !ok {
		return fmt.Errorf("the release has no %s", o.Asset)
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if left := cooldownLeft(o.ResultPath, now()); left > 0 {
		return errors.New(cooldownMessage(left))
	}
	in := *o.Installer
	newPath, err := release.CopyVerified(p(o.Asset), filepath.Dir(in.Target), want)
	if err != nil {
		return err
	}
	// From here on the service is stopped, swapped and restarted: that is the run the cooldown counts. Runs
	// refused above change nothing and do not move the time, so asking again and again cannot keep an update
	// away for ever.
	if err := writeAtomic(lastApplyPath(o.ResultPath), []byte(strconv.FormatInt(now().Unix(), 10)+"\n")); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("cannot record the time of this run: %w", err)
	}
	in.Healthy = func(ctx context.Context) error { return o.Healthy(ctx, ch.Version) }
	// after a rollback the installed version runs again: that one is what the check must find
	in.HealthyPrevious = func(ctx context.Context) error { return o.Healthy(ctx, o.CurrentVersion) }
	if in.Logf == nil {
		in.Logf = func(f string, a ...any) { slog.Info("apply-update: " + fmt.Sprintf(f, a...)) }
	}
	return in.Install(ctx, newPath)
}

// realDir refuses a stage folder (or its parent) that is a symlink or (Windows) a junction or other reparse
// point: the installer runs as root / LocalSystem, the stage belongs to the agent's account.
func realDir(dir string) error {
	for _, d := range []string{filepath.Dir(dir), dir} {
		st, err := os.Lstat(d)
		if err != nil {
			return fmt.Errorf("nothing staged: %w", err)
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || isReparsePoint(st) {
			return fmt.Errorf("%s is not a plain folder", d)
		}
	}
	return nil
}

// plainIfExists refuses a folder that is a symlink or reparse point (a missing one is fine: it is created).
func plainIfExists(dir string) error {
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || isReparsePoint(st) {
		return fmt.Errorf("%s is not a plain folder", dir)
	}
	return nil
}

func writeResult(path string, r UpdateResult) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeAtomic(path, b)
}

// writeAtomic replaces a file in the installer's own folder in one step (readable by everyone: the agent
// reads it).
func writeAtomic(path string, b []byte) error {
	if err := plainIfExists(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".result-*")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && runtime.GOOS != "windows" {
		err = os.Chmod(f.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// DefaultUpdaterOptions are the real updater's settings: GitHub, this platform's paths and installer.
func DefaultUpdaterOptions(cfg *Config, version, releaseKey string) (UpdaterOptions, error) {
	c, err := release.NewClient(cfg.SelfUpdate.Repo, "fairy-agent/"+version)
	if err != nil {
		return UpdaterOptions{}, err
	}
	key, kerr := release.ParsePublicKey(releaseKey)
	stage, result := UpdatePaths(cfg)
	cfgPath := cfg.Path()
	return UpdaterOptions{Version: version, Key: key, KeyErr: kerr, Client: c, StageDir: stage, ResultPath: result,
		Asset: release.AssetName(release.AgentProgram, runtime.GOOS, runtime.GOARCH),
		Apply: func(ctx context.Context) error { return startInstaller(ctx, cfgPath) }, Ready: installerReady}, nil
}

// ApplyUpdate is `fairy-agent apply-update`: install what the agent staged (see the top of this file).
func ApplyUpdate(ctx context.Context, cfg *Config, version, releaseKey string) error {
	key, err := release.ParsePublicKey(releaseKey)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	stage, result := UpdatePaths(cfg)
	in := installerFor(exe)
	res := ApplyStaged(ctx, ApplyOptions{StageDir: stage, ResultPath: result, Key: key, CurrentVersion: version,
		Asset: release.AssetName(release.AgentProgram, runtime.GOOS, runtime.GOARCH), Installer: in,
		Healthy: func(ctx context.Context, want string) error {
			if err := serviceRunning(ctx); err != nil {
				return err
			}
			// want is a newer release or, after a rollback, this very version: both know /health
			return CheckRunning(ctx, cfg, want)
		}})
	if !res.OK {
		return errors.New(res.Message)
	}
	return nil
}

// NewUpdateCLI is `fairy-agent update` on the machine itself (root on Linux, Administrator on Windows), like
// `tailscale update`: the same signed download, swap, restart, health check and rollback as the panel's Update
// button, without the stage (the downloading process is already privileged). cfg may be nil (no config file):
// then the official repository is used and the health check only asks the service manager.
func NewUpdateCLI(ctx context.Context, cfg *Config, version, releaseKey string) (*release.CLI, error) {
	repo := release.AgentRepo
	if cfg != nil {
		repo = cfg.SelfUpdate.Repo
	}
	c, err := release.NewClient(repo, "fairy-agent/"+version)
	if err != nil {
		return nil, err
	}
	key, err := release.ParsePublicKey(releaseKey)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	running := serviceRunning(ctx) == nil
	cli := &release.CLI{Client: c, Key: key, Program: release.AgentProgram, Current: version, Target: exe,
		Asset: release.AssetName(release.AgentProgram, runtime.GOOS, runtime.GOARCH), Out: os.Stdout, In: os.Stdin,
		RunNew: func(path string) (string, error) {
			out, err := exec.Command(path, "version").Output()
			return string(out), err
		},
		Installer: func(target, want string) *release.Installer {
			in := installerFor(target)
			if !running { // service stopped or not installed: swap only, nothing to restart or check
				in.Stop = nil
				in.Start = func(context.Context) error { return nil }
				in.Healthy = func(context.Context) error { return nil }
				return in
			}
			healthy := func(v string) func(context.Context) error {
				return func(ctx context.Context) error {
					if err := serviceRunning(ctx); err != nil {
						return err
					}
					if cfg == nil {
						return nil
					}
					return checkRunningFrom(ctx, cfg, version, v)
				}
			}
			// after a rollback this binary's own version runs again
			in.Healthy, in.HealthyPrevious = healthy(want), healthy(version)
			return in
		}}
	if !running {
		fmt.Fprintln(os.Stdout, "(the fairy-agent service is not running: the binary is replaced but not started)")
	}
	if cfg != nil {
		if _, result := UpdatePaths(cfg); result != "" {
			cli.Done = func(from, to string, err error) {
				idb := make([]byte, 8)
				_, _ = rand.Read(idb)
				r := UpdateResult{ID: hex.EncodeToString(idb), OK: err == nil, From: from, To: to, At: float64(time.Now().Unix()),
					Message: "updated from " + from + " to " + to + " (fairy-agent update on the machine)"}
				if err != nil {
					r.Message = "update to " + to + " failed (fairy-agent update on the machine): " + err.Error()
				}
				_ = writeResult(result, r)
			}
		}
	}
	return cli, nil
}

// StartUpdaterService starts the installer (Windows: the fairy-agent-update service; the helper calls this
// for apply_update when the agent may not start it itself).
func StartUpdaterService(ctx context.Context) error { return startInstaller(ctx, "") }
