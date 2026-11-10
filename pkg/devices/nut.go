package devices

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Limits on what an upsd may send (a broken or hostile one must not exhaust the agent's or the panel's memory):
// upsd's own lines are a few hundred bytes, a full LIST VAR a few kilobytes.
const (
	NUTMaxLine  = 4096    // one reply line
	NUTMaxReply = 1 << 20 // everything read over one connection
	NUTMaxUPS   = 64      // UPSes taken from LIST UPS
	NUTMaxLines = 5000    // lines in one LIST reply
)

var errNUTTooLarge = errors.New("nut: reply too large")

// capReader fails once more than n bytes have been read.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, errNUTTooLarge
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	k, err := c.r.Read(p)
	c.n -= int64(k)
	return k, err
}

func nutUnescape(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, `\"`, `"`), `\\`, `\`)
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return nutUnescape(v)
}

// ParseNUTVarLine parses `VAR <ups> <name> "<value>"`.
func ParseNUTVarLine(line, ups string) (string, string, bool) {
	prefix := "VAR " + ups + " "
	if !strings.HasPrefix(line, prefix) {
		return "", "", false
	}
	name, value, _ := strings.Cut(line[len(prefix):], " ")
	return name, unquote(value), true
}

// ParseNUTUPSLine parses `UPS <name> "<description>"` from LIST UPS.
func ParseNUTUPSLine(line string) (string, string, bool) {
	if !strings.HasPrefix(line, "UPS ") {
		return "", "", false
	}
	name, desc, _ := strings.Cut(line[4:], " ")
	return name, unquote(desc), true
}

// NUTUPS is one UPS as listed by upsd, with all its variables.
type NUTUPS struct {
	Name, Description string
	Vars              map[string]string
}

type nutConn struct {
	c net.Conn
	r *bufio.Reader
}

func (n *nutConn) cmd(line string) error {
	_, err := n.c.Write([]byte(line + "\n"))
	return err
}

func (n *nutConn) readline() (string, error) {
	b, err := n.r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return "", Errf("nut: reply line longer than %d bytes", NUTMaxLine)
	case errors.Is(err, errNUTTooLarge):
		return "", Errf("nut: reply larger than %d bytes", NUTMaxReply)
	case err != nil && len(b) == 0:
		return "", Errf("nut: connection closed")
	}
	text := strings.TrimRight(string(b), "\r\n")
	if strings.HasPrefix(text, "ERR") {
		return "", Errf("nut: %s", text)
	}
	return text, nil
}

func (n *nutConn) listing(what string) ([]string, error) {
	if err := n.cmd("LIST " + what); err != nil {
		return nil, Errf("connection failed")
	}
	first, err := n.readline()
	if err != nil {
		return nil, err
	}
	if first != "BEGIN LIST "+what {
		return nil, Errf("nut: unexpected reply")
	}
	var lines []string
	for {
		l, err := n.readline()
		if err != nil {
			return nil, err
		}
		if l == "END LIST "+what {
			return lines, nil
		}
		lines = append(lines, l)
		if len(lines) > NUTMaxLines {
			return nil, Errf("nut: reply too long")
		}
	}
}

// NUTReadAll reads UPS variables over one connection: optional login, LIST UPS (unless names given), LIST VAR
// for each. Read-only: never sends INSTCMD / SET VAR / FSD.
func NUTReadAll(ctx context.Context, host string, port int, username, password string, timeout time.Duration, names []string) ([]NUTUPS, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, describeHTTP(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout + 2*time.Second))
	n := &nutConn{c: c, r: bufio.NewReaderSize(&capReader{r: c, n: NUTMaxReply}, NUTMaxLine)}
	if username != "" {
		if err := n.cmd("USERNAME " + username); err != nil {
			return nil, Errf("connection failed")
		}
		if _, err := n.readline(); err != nil {
			return nil, err
		}
		if err := n.cmd("PASSWORD " + password); err != nil {
			return nil, Errf("connection failed")
		}
		if _, err := n.readline(); err != nil {
			return nil, err
		}
	}
	type pair struct{ name, desc string }
	var upses []pair
	if len(names) > 0 {
		for _, nm := range names {
			upses = append(upses, pair{nm, ""})
		}
	} else {
		lines, err := n.listing("UPS")
		if err != nil {
			return nil, err
		}
		for _, l := range lines {
			if nm, desc, ok := ParseNUTUPSLine(l); ok && len(upses) < NUTMaxUPS {
				upses = append(upses, pair{nm, desc})
			}
		}
	}
	var out []NUTUPS
	for _, u := range upses {
		lines, err := n.listing("VAR " + u.name)
		if err != nil {
			return nil, err
		}
		vars := map[string]string{}
		for _, l := range lines {
			if k, v, ok := ParseNUTVarLine(l, u.name); ok {
				vars[k] = v
			}
		}
		out = append(out, NUTUPS{u.name, u.desc, vars})
	}
	_ = n.cmd("LOGOUT")
	return out, nil
}

// numVar is the first of these variables that holds a number, nil when none does. upsd sends text, and
// strconv reads "NaN", "Inf" and "Infinity" as numbers: those and numbers beyond MaxMagnitude count as missing.
func numVar(v map[string]string, keys ...string) *float64 {
	for _, k := range keys {
		if s, ok := v[k]; ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && Finite(f) {
				return &f
			}
		}
	}
	return nil
}

func strVar(v map[string]string, keys ...string) *string {
	for _, k := range keys {
		if s, ok := v[k]; ok && s != "" {
			return &s
		}
	}
	return nil
}

// NUTWatts returns (watts, input volts, output amps); watts are estimated from load% x nominal when realpower is
// missing (never from a negative load or nominal power, and nil when the product is not a possible number).
func NUTWatts(v map[string]string) (watts, volts, amps *float64) {
	watts = numVar(v, "ups.realpower")
	if watts == nil {
		watts = nutEstimate(notNegative(numVar(v, "ups.load")), notNegative(numVar(v, "ups.realpower.nominal")))
	}
	return watts, numVar(v, "input.voltage"), numVar(v, "output.current")
}

// notNegative returns p when it is a possible number that is not below zero.
func notNegative(p *float64) *float64 { return NumIn(p, 0, MaxMagnitude) }

// nutEstimate is load % x nominal watts, to 0.1 W; nil when either is missing or nominal is 0.
func nutEstimate(load, nominal *float64) *float64 {
	if load == nil || nominal == nil || *nominal == 0 {
		return nil
	}
	return numRound(*load**nominal/100, 1)
}
