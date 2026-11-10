//go:build unix

package enroll

import "syscall"

// openStateFlags: a state file is never a symbolic link, and opening it must not wait (a FIFO under that name
// would block the reader, which may be root: `fairy-agent pair-status`).
const openStateFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// createStateFlags: the temporary file is new (O_EXCL, set by the caller) and never reached through a link.
const createStateFlags = syscall.O_NOFOLLOW
