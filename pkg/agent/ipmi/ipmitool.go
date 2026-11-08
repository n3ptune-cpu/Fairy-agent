package ipmi

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Ipmitool runs `ipmitool raw` for each request: in-band (Linux /dev/ipmi0) when Host is empty, else
// IPMI-over-LAN (lanplus) to Host with Username and a password passed in the IPMI_PASSWORD environment variable
// (ipmitool -E), never on the command line.
type Ipmitool struct {
	Path     string
	Host     string
	Username string
	Password string
	Env      []string             // base environment (without the agent's secrets)
	SysAttr  *syscall.SysProcAttr // Windows: no console window, low priority

	mu sync.Mutex // one request at a time: the BMC handles them serially anyway
}

var rspRe = regexp.MustCompile(`rsp=0x([0-9a-fA-F]{2})`)

// ParseRawOutput turns ipmitool's hex dump (" 01 02\n 03") into bytes.
func ParseRawOutput(out string) ([]byte, error) {
	var b []byte
	for _, f := range strings.Fields(out) {
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("unexpected ipmitool output")
		}
		b = append(b, byte(v))
	}
	return b, nil
}

// Args returns the ipmitool arguments for one raw request (exported for tests).
func (t *Ipmitool) Args(netfn, cmd byte, data []byte) []string {
	var args []string
	if t.Host != "" {
		args = append(args, "-I", "lanplus", "-H", t.Host, "-U", t.Username, "-E")
	}
	args = append(args, "raw", fmt.Sprintf("0x%02x", netfn), fmt.Sprintf("0x%02x", cmd))
	for _, d := range data {
		args = append(args, fmt.Sprintf("0x%02x", d))
	}
	return args
}

// Raw runs one request.
func (t *Ipmitool) Raw(ctx context.Context, netfn, cmd byte, data []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := exec.CommandContext(ctx, t.Path, t.Args(netfn, cmd, data)...)
	c.Env = t.Env
	if t.Host != "" {
		c.Env = append(append([]string{}, t.Env...), "IPMI_PASSWORD="+t.Password)
	}
	c.SysProcAttr = t.SysAttr
	var stdout, stderr strings.Builder
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	if err != nil {
		if m := rspRe.FindStringSubmatch(stderr.String()); m != nil {
			v, _ := strconv.ParseUint(m[1], 16, 8)
			return nil, &CompletionError{Code: byte(v)}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, errors.New("ipmitool failed (is the BMC reachable and the IPMI driver loaded?)")
		}
		return nil, errors.New("cannot run ipmitool")
	}
	return ParseRawOutput(stdout.String())
}

// Close does nothing (no persistent connection).
func (t *Ipmitool) Close() {}
