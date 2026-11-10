package configedit

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// copyAttrs does nothing on Windows: the new file takes the folder's permissions and belongs to whoever runs
// this. The old file's own owner and permissions are deliberately not copied (see WriteFile).
func copyAttrs(*os.File, string, os.FileInfo) error { return nil }

func syncDir(string) {}

// checkOld refuses to edit a config.yaml that is a link, or that someone other than Administrators, SYSTEM or
// TrustedInstaller owns: another account made that file (under C:\ProgramData ordinary users can create
// files, and whoever creates one owns it), so what it says is not the administrator's. `fairy-agent
// setup-self-update` moves such a file aside and writes a starter. The file is opened itself, never through a
// link, and its owner is read from that handle.
func checkOld(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("%s is a link or a folder, not a plain file", path)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: cannot read its owner: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New(path + ": cannot read its owner")
	}
	if !collect.TrustedOwner(owner.String()) {
		return fmt.Errorf("%s is owned by %s, not by Administrators or SYSTEM, so it is not edited: another account made it. "+
			`As Administrator run: & "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update   (it moves the file aside and writes a starter)`,
			path, owner.String())
	}
	return nil
}
