package configedit

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile replaces an existing config.yaml with data in one step: a new file next to it gets the old file's
// owner, permissions and (Linux) SELinux label / ACL, is flushed to disk, then renamed over the old one, so a
// crash leaves either the old or the new file, never half of one. On Windows the new file inherits the folder's
// permissions; when the old file's owner or access list differ from that (someone changed them by hand), the
// file is rewritten in place instead, which keeps them exactly.
func WriteFile(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config.yaml.new-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := copyAttrs(tmp, path, st); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot give the new file the old one's owner and permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !sameSecurity(name, path) {
		return writeInPlace(path, data)
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
