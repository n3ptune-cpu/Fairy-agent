//go:build windows

package linktest

import (
	"errors"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dirLink makes a junction, the way `mklink /J link target` does: an empty folder that gets a mount point
// reparse buffer naming target. Ordinary users may do this on NTFS.
func dirLink(target, link string) (string, error) {
	// A name that was removed a moment ago (the tests swap a folder for a link) can still be taken for an
	// instant on Windows, while something else has the removed thing open: creating it then says "Access is
	// denied". That passes by itself.
	err := os.Mkdir(link, 0o777)
	for i := 0; i < 50 && errors.Is(err, windows.ERROR_ACCESS_DENIED); i++ {
		time.Sleep(10 * time.Millisecond)
		err = os.Mkdir(link, 0o777)
	}
	if err != nil {
		return "", err
	}
	if err := setMountPoint(link, target); err != nil {
		_ = os.Remove(link)
		return "", err
	}
	return Junction, nil
}

// setMountPoint writes the reparse data: REPARSE_DATA_BUFFER with the MountPointReparseBuffer member (winnt.h /
// ntifs.h). The substitute name is the NT path (\??\C:\...), the print name the path as typed; both end in a
// NUL that their lengths do not count.
func setMountPoint(link, target string) error {
	sub, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		return err
	}
	prn, err := windows.UTF16FromString(target)
	if err != nil {
		return err
	}
	const header = 8  // ReparseTag, ReparseDataLength, Reserved
	const offsets = 8 // SubstituteNameOffset, SubstituteNameLength, PrintNameOffset, PrintNameLength
	pathBytes := 2 * (len(sub) + len(prn))
	if header+offsets+pathBytes > windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
		return &os.PathError{Op: "junction", Path: target, Err: windows.ERROR_FILENAME_EXCED_RANGE}
	}
	buf := make([]byte, header+offsets+pathBytes)
	put16 := func(at int, v uint16) { buf[at], buf[at+1] = byte(v), byte(v>>8) }
	put16(0, uint16(windows.IO_REPARSE_TAG_MOUNT_POINT&0xffff))
	put16(2, uint16(windows.IO_REPARSE_TAG_MOUNT_POINT>>16))
	put16(4, uint16(offsets+pathBytes)) // ReparseDataLength: everything after the header
	put16(8, 0)                         // SubstituteNameOffset
	put16(10, uint16(2*(len(sub)-1)))   // SubstituteNameLength
	put16(12, uint16(2*len(sub)))       // PrintNameOffset
	put16(14, uint16(2*(len(prn)-1)))   // PrintNameLength
	at := header + offsets
	for _, s := range [][]uint16{sub, prn} {
		for _, c := range s {
			put16(at, c)
			at += 2
		}
	}
	p, err := windows.UTF16PtrFromString(link)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: link, Err: err}
	}
	defer windows.CloseHandle(h)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, (*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)), nil, 0, &n, nil); err != nil {
		return &os.PathError{Op: "set the junction of", Path: link, Err: err}
	}
	return nil
}
