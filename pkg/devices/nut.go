package devices

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

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
	raw, err := n.r.ReadString('\n')
	if err != nil {
		if raw == "" {
			return "", Errf("nut: connection closed")
		}
	}
	text := strings.TrimRight(raw, "\r\n")
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
		if len(lines) > 5000 {
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
	n := &nutConn{c: c, r: bufio.NewReaderSize(c, 8192)}
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
			if nm, desc, ok := ParseNUTUPSLine(l); ok {
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

func numVar(v map[string]string, keys ...string) *float64 {
	for _, k := range keys {
		if s, ok := v[k]; ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
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
// missing.
func NUTWatts(v map[string]string) (watts, volts, amps *float64) {
	watts = numVar(v, "ups.realpower")
	if watts == nil {
		if load, nom := numVar(v, "ups.load"), numVar(v, "ups.realpower.nominal"); load != nil && nom != nil && *nom != 0 {
			w := round(*load**nom/100, 1)
			watts = &w
		}
	}
	return watts, numVar(v, "input.voltage"), numVar(v, "output.current")
}
