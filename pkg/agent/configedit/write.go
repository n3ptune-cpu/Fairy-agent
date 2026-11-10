package configedit

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile replaces an existing config.yaml with data in one step: a new file next to it gets the old file's
// owner, permissions and (Linux) SELinux label / ACL, is flushed to disk, then renamed over the old one, so a
// crash leaves either the old or the new file, never half of one.
//
// The old file is never written to. On Windows the new file takes the folder's permissions and belongs to
// whoever runs this (an administrator); owner and permissions someone set on the old file by hand are not
// carried over. Until 0.5.3 such a file was rewritten in place to keep them, which also kept a file that
// another account had prepared, with that account still its owner. Such a file is now refused (checkOld):
// replacing it would hand its content, which someone else wrote, on to a file administrators own.
func WriteFile(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if err := checkOld(path); err != nil {
		return err
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}
