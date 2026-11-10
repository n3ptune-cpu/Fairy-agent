//go:build !unix

package enroll

// Windows: the state folder's permissions (administrators, SYSTEM, the service) decide who may put a file there.
const (
	openStateFlags   = 0
	createStateFlags = 0
)
