//go:build windows

package winpipe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Access the agent gets on the pipe: read and write data and attributes, read the security descriptor,
// synchronize. Not FILE_APPEND_DATA, which on a pipe is FILE_CREATE_PIPE_INSTANCE: the agent can never create
// an instance of the helper's pipe name itself.
const (
	ClientAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	agentMask    = 0x120183 // FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE
)

// SDDL is the pipe's security descriptor: network logons denied; SYSTEM and Administrators full control; the
// agent's service SID read / write only.
func SDDL(agentSID string) string {
	return fmt.Sprintf("D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x%x;;;%s)", agentMask, agentSID)
}

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
	errTimeout                     = os.ErrDeadlineExceeded
	errClosed                      = errors.New("pipe closed")
)

// Conn is one end of a connected pipe instance (overlapped handle), with a deadline for each read and write.
type Conn struct {
	h      windows.Handle
	ev     windows.Handle
	server bool
	stop   <-chan struct{} // server: the listener's context; a pending read or write ends with it
	mu     sync.Mutex      // one operation at a time
	dlMu   sync.Mutex
	dl     time.Time
	closed bool
}

func newConn(h windows.Handle, server bool) (*Conn, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return &Conn{h: h, ev: ev, server: server}, nil
}

// SetDeadline sets the deadline for the following reads and writes (zero: none).
func (c *Conn) SetDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.dl = t
	c.dlMu.Unlock()
	return nil
}

// wait waits for the pending operation's event until the deadline or stop, in steps of at most 250 ms.
// It reports whether the operation completed.
func (c *Conn) wait() bool {
	c.dlMu.Lock()
	dl := c.dl
	c.dlMu.Unlock()
	for {
		step := uint32(250)
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				step = 0
			} else if d < 250*time.Millisecond {
				step = uint32(d.Milliseconds() + 1)
			}
		}
		ev, _ := windows.WaitForSingleObject(c.ev, step)
		if ev == windows.WAIT_OBJECT_0 {
			return true
		}
		if !dl.IsZero() && !time.Now().Before(dl) {
			return false
		}
		select {
		case <-c.stop:
			return false
		default:
		}
	}
}

// do runs one overlapped operation and waits for it, cancelling it at the deadline.
func (c *Conn) do(op func(*windows.Overlapped) error) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errClosed
	}
	ov := &windows.Overlapped{HEvent: c.ev}
	err := op(ov)
	timedOut := false
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		if !c.wait() {
			_ = windows.CancelIoEx(c.h, ov)
			timedOut = true
		}
	} else if err != nil {
		return 0, err
	}
	var n uint32
	err = windows.GetOverlappedResult(c.h, ov, &n, true)
	runtime.KeepAlive(ov)
	if timedOut && (err == nil || errors.Is(err, windows.ERROR_OPERATION_ABORTED)) {
		if err == nil && n > 0 {
			return n, nil // completed just as it was cancelled
		}
		return n, errTimeout
	}
	return n, err
}

// Read reads into p.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := c.do(func(ov *windows.Overlapped) error { return windows.ReadFile(c.h, p, nil, ov) })
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
		return int(n), io.EOF
	}
	if err == nil && n == 0 {
		return 0, io.EOF
	}
	return int(n), err
}

// Write writes all of p.
func (c *Conn) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		n, err := c.do(func(ov *windows.Overlapped) error { return windows.WriteFile(c.h, p[done:], nil, ov) })
		done += int(n)
		if err != nil {
			return done, err
		}
		if n == 0 {
			return done, errClosed
		}
	}
	return done, nil
}

// Close flushes (server: so the client gets the last answer), disconnects and closes.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.server {
		_ = windows.FlushFileBuffers(c.h)
		_ = windows.DisconnectNamedPipe(c.h)
	}
	windows.CloseHandle(c.ev)
	return windows.CloseHandle(c.h)
}

// Client describes a verified client (for the audit log).
type Client struct {
	PID uint32
	SID string
}

func (c Client) String() string { return fmt.Sprintf("%s pid %d", c.SID, c.PID) }

// Allowed decides from a client's (identification-level) token whether it may talk to the helper.
type Allowed func(tok windows.Token) bool

// Serve listens on name until ctx ends and calls handle (in its own goroutine, at most maxConns at a time)
// for every client allow accepts; any other client is disconnected at once and reported to reject. The first
// instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE (fails if anyone else already owns the name), and one
// instance is always kept listening, so the name is never free for another process to take over. Remote
// clients are refused by the pipe itself (PIPE_REJECT_REMOTE_CLIENTS) and by the DACL.
//
// When another process already holds the name (it can be taken while the helper is stopped: during an update,
// after Stop in the panel, after a crash), Serve does not give up: it tries again after RetryDelay, for as long
// as it takes, and tells held who holds the name (holder), why creating failed and when the next try is. When
// the name is finally its own, held is called once more with a nil error. The agent never talks to such a
// process (Dial checks the server's process id against the service manager's).
func Serve(ctx context.Context, name, sddl string, maxConns int, allow Allowed,
	handle func(ctx context.Context, c *Conn, who Client), reject func(who Client, why string),
	held func(holder string, err error, retryIn time.Duration)) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("pipe security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	n16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	create := func(first bool) (windows.Handle, error) {
		flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
		if first {
			flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
		}
		return windows.CreateNamedPipe(n16, flags,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
			uint32(maxConns+2), 64<<10, 64<<10, 0, sa)
	}
	var h windows.Handle
	for attempt := 0; ; attempt++ {
		h, err = create(true)
		if err == nil {
			if attempt > 0 && held != nil {
				held("", nil, 0)
			}
			break
		}
		if !nameHeld(err) {
			return fmt.Errorf("creating the pipe %s: %w", name, err)
		}
		d := RetryDelay(attempt)
		if held != nil {
			held(pipeHolder(n16), err, d)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d):
		}
	}
	sem := make(chan struct{}, maxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			windows.CloseHandle(h)
			return nil
		}
		c, err := newConn(h, true)
		if err == nil {
			c.stop = ctx.Done()
		}
		if err != nil {
			<-sem
			return err
		}
		if err := c.connect(ctx); err != nil {
			<-sem
			c.Close()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		next, err := create(false) // keep one instance listening before handing this one over
		for err != nil && ctx.Err() == nil {
			time.Sleep(200 * time.Millisecond)
			next, err = create(false)
		}
		who, ok, why := verifyOnOwnThread(c.h, allow)
		if !ok {
			<-sem
			c.Close()
			reject(who, why)
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				defer c.Close()
				handle(ctx, c, who)
			}()
		}
		if ctx.Err() != nil {
			if next != 0 {
				windows.CloseHandle(next)
			}
			return nil
		}
		h = next
	}
}

// nameHeld reports whether creating the first instance failed because the name already exists: Windows answers
// ERROR_ACCESS_DENIED to FILE_FLAG_FIRST_PIPE_INSTANCE then, or ERROR_PIPE_BUSY when the other pipe allows no
// further instance.
func nameHeld(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY)
}

// pipeHolder describes the process that serves the pipe name now ("pid 1234, C:\path\program.exe"), for the
// log. It opens the pipe as a client that allows the server nothing (anonymous: the server cannot identify it,
// let alone act as it), asks only for the right to read attributes, sends and reads nothing, and closes at
// once. The program's path comes from OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION (no access to the
// process's memory).
func pipeHolder(n16 *uint16) string {
	h, err := windows.CreateFile(n16, windows.FILE_READ_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
	if err != nil {
		return "unknown process (the pipe could not be asked: " + err.Error() + ")"
	}
	defer windows.CloseHandle(h)
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil || pid == 0 {
		return "unknown process"
	}
	who := fmt.Sprintf("pid %d", pid)
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return who
	}
	defer windows.CloseHandle(p)
	buf := make([]uint16, windows.MAX_PATH*4)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(p, 0, &buf[0], &n); err != nil || n == 0 {
		return who
	}
	return who + ", " + windows.UTF16ToString(buf[:n])
}

// connect waits for a client (ConnectNamedPipe, overlapped) until ctx ends.
func (c *Conn) connect(ctx context.Context) error {
	ov := &windows.Overlapped{HEvent: c.ev}
	err := windows.ConnectNamedPipe(c.h, ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return err
	}
	for {
		ev, _ := windows.WaitForSingleObject(c.ev, 250)
		if ev == windows.WAIT_OBJECT_0 {
			break
		}
		if ctx.Err() != nil {
			_ = windows.CancelIoEx(c.h, ov)
			var n uint32
			_ = windows.GetOverlappedResult(c.h, ov, &n, true)
			runtime.KeepAlive(ov)
			return ctx.Err()
		}
	}
	var n uint32
	err = windows.GetOverlappedResult(c.h, ov, &n, true)
	runtime.KeepAlive(ov)
	return err
}

type verdict struct {
	who Client
	ok  bool
	why string
}

// verifyOnOwnThread runs verify in a goroutine of its own: if reverting the impersonation ever failed, that
// goroutine's thread stays locked and Go ends the thread with it, instead of the listener running on as the
// client.
func verifyOnOwnThread(h windows.Handle, allow Allowed) (Client, bool, string) {
	ch := make(chan verdict, 1)
	go func() {
		who, ok, why := verify(h, allow)
		ch <- verdict{who, ok, why}
	}()
	v := <-ch
	return v.who, v.ok, v.why
}

// verify identifies the client by impersonating it (at identification level, which is all the client grants)
// on a locked thread, reading its token and reverting at once.
func verify(h windows.Handle, allow Allowed) (Client, bool, string) {
	var who Client
	_ = windows.GetNamedPipeClientProcessId(h, &who.PID)
	runtime.LockOSThread()
	if r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
		runtime.UnlockOSThread()
		return who, false, "cannot identify the client: " + e.Error()
	}
	var tok windows.Token
	oerr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if err := windows.RevertToSelf(); err != nil {
		// never keep running as someone else: leave the thread locked, so it ends with this goroutine
		if oerr == nil {
			tok.Close()
		}
		return who, false, "cannot revert impersonation"
	}
	runtime.UnlockOSThread()
	if oerr != nil {
		return who, false, "cannot read the client's token: " + oerr.Error()
	}
	defer tok.Close()
	if u, err := tok.GetTokenUser(); err == nil {
		who.SID = u.User.Sid.String()
	}
	if !allow(tok) {
		return who, false, "not the fairy-agent service, SYSTEM or an administrator"
	}
	return who, true, ""
}

// MemberOf is an Allowed that accepts tokens with any of sids as their user or an enabled group (the agent's
// service SID: its user SID as a virtual account, an enabled group under LocalService; SYSTEM; Administrators,
// which a non-elevated administrator's token has only as a deny-only group).
func MemberOf(sids ...*windows.SID) Allowed {
	return func(tok windows.Token) bool {
		for _, s := range sids {
			if ok, err := tok.IsMember(s); err == nil && ok {
				return true
			}
		}
		return false
	}
}

// Dial connects to the pipe and checks that its server process is serverPID() (the helper service's process
// as the service manager reports it), so a process that took the name while the helper was stopped is never
// talked to. The client allows identification only: the helper can see who it is but cannot act as it.
//
// owner (may be nil) also looks at who owns the pipe, read from the connected handle (owner.go): a process id
// can be used again, a pipe's owner cannot be borrowed. In this release it only reports unless owner.Enforce.
func Dial(ctx context.Context, name string, serverPID func() (uint32, error), owner *OwnerCheck) (*Conn, error) {
	n16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	// READ_CONTROL lets the owner be read. The helper's pipe gives it to the agent's account and to
	// administrators; if a pipe does not, the connection is made without it and the owner counts as not read
	// (so the look can never keep the agent from a pipe it reached before).
	access := uint32(ClientAccess)
	if owner != nil {
		access |= windows.READ_CONTROL
	}
	var h windows.Handle
	for {
		h, err = windows.CreateFile(n16, access, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && access != ClientAccess {
			access = ClientAccess
			continue
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, ErrNoPipe
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	want, err := serverPID()
	if err != nil || want == 0 || pid != want {
		windows.CloseHandle(h)
		return nil, ErrNotHelper
	}
	if owner != nil {
		sid, oerr := "", error(windows.ERROR_ACCESS_DENIED)
		if access&windows.READ_CONTROL != 0 {
			sid, oerr = pipeOwner(h)
		}
		if err := owner.Decide(name, sid, oerr); err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
	}
	return newConn(h, false)
}

// pipeOwner is the owner SID of the pipe behind a connected handle (which needs READ_CONTROL).
func pipeOwner(h windows.Handle) (string, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	sid, _, err := sd.Owner()
	if err != nil {
		return "", err
	}
	if sid == nil {
		return "", nil
	}
	return sid.String(), nil
}
