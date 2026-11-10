package main

// Writing the pairing state as Administrator into state\, a folder the agent's own account can write.
//
// `fairy-agent join` checks state\ (a plain folder with the agent folders' permissions) and then put
// pairing.json into it by path: a temporary file "state\.pairing-....tmp", renamed to "state\pairing.json". A
// path through state\ is not a fixed thing, though: the agent's account can empty that folder and turn it into
// a junction between the check and the write, and the administrator's file then lands in a folder of the
// account's choosing, replacing a pairing.json there (rule 1 of datadir.go, in its smallest form).
//
// Now the folder is opened once and everything is done relative to that open folder (os.Root: the new file is
// created and renamed inside the folder the handle stands for, wherever a name leads by then). And the open
// folder must be the very folder that was looked at without following a link: same volume, same file id.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// writeStateIn, when set (Windows), is how join writes the pairing state into the state folder dir.
var writeStateIn func(dir string, st enroll.State) error

// folderItself looks at dir without following a link (a link is refused) and returns what it is, read from
// the opened folder, which stays open until done is called: its identity cannot pass to another folder in
// between. Windows replaces it (datadir_windows.go: the folder is opened itself with
// FILE_FLAG_OPEN_REPARSE_POINT); elsewhere lstat gives the folder's own device and inode in one call.
var folderItself = func(dir string) (fi os.FileInfo, done func(), err error) {
	fi, err = os.Lstat(dir)
	return fi, func() {}, err
}

// Test hooks: the agent's account acting between two steps of writeInFolder.
var (
	beforeFolderOpened func()
	afterFolderOpened  func()
)

// writePairingState writes st as pairing.json into the state folder dir (see the top of this file). The bytes
// are those enroll.WriteState writes.
func writePairingState(dir string, st enroll.State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeInFolder(dir, "pairing.json", ".pairing-", append(b, '\n'))
}

// writeInFolder puts data into the file name directly in folder dir, replacing an existing file in one step.
// Nothing is reached by a path through dir: dir is opened once, checked to be the plain folder that is under
// that name, and the file is created and renamed relative to the open folder.
func writeInFolder(dir, name, tmpPrefix string, data []byte) error {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("%q is not a file name", name)
	}
	itself, done, err := folderItself(dir)
	if err != nil {
		return err
	}
	defer done()
	if m := itself.Mode(); !m.IsDir() || m&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is not a plain folder (a link?): nothing was written%s", dir, repairHint)
	}
	if beforeFolderOpened != nil {
		beforeFolderOpened()
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(itself, opened) {
		return fmt.Errorf("%s became a link to another folder while it was being written to: nothing was written there. "+
			"Something running under the agent's own account did that: stop the fairy-agent service and look at this PC%s", dir, repairHint)
	}
	if afterFolderOpened != nil {
		afterFolderOpened()
	}
	var tmp string
	var f *os.File
	for i := 0; ; i++ {
		var r [8]byte
		if _, err := rand.Read(r[:]); err != nil {
			return err
		}
		tmp = tmpPrefix + hex.EncodeToString(r[:]) + ".tmp"
		// O_EXCL: the name did not exist, so this is a file this process made, whatever else is in the folder
		f, err = root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) && i < 100 {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name) // replaces a file or a link under the name; never follows it
	}
	if err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("writing %s in %s: %w", name, dir, err)
	}
	return nil
}
