package main

// `fairy-agent join --proxmox` (install.sh --proxmox, run as root on a Proxmox VE node): make the panel a
// read-only API token on this node and keep it in the pairing state, so the panel picks it up with the agent's
// tokens and polls the node through the Proxmox API without anyone copying a token. Idempotent:
//
//	pveum user add fairy@pve --comment "Fairy panel, read-only"        (an existing user is fine)
//	pveum aclmod / --users fairy@pve --roles PVEAuditor                 (read-only role on everything)
//	pveum user token remove fairy@pve panel-<node>                      (only when that same token exists)
//	pveum user token add fairy@pve panel-<node> --privsep 0 --output-format json
//
// The secret is read from pveum's JSON and never printed. Standalone nodes only: in a cluster of more than one
// node this part is skipped (the agent still installs).

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

const (
	pveUser      = "fairy@pve"
	pveRootCA    = "/etc/pve/pve-root-ca.pem"
	pveNodeCert  = "/etc/pve/local/pve-ssl.pem"
	pveProxyCert = "/etc/pve/local/pveproxy-ssl.pem" // a custom (e.g. ACME) certificate, served instead
	pveCorosync  = "/etc/pve/corosync.conf"
)

// pveHost is what the Proxmox step needs from the machine (fakes in tests).
type pveHost struct {
	run       func(name string, args ...string) ([]byte, error) // combined output
	readFile  func(string) ([]byte, error)
	exists    func(string) bool
	hostname  func() (string, error)
	tailscale func() string // this node's MagicDNS name ("" unknown)
}

func realPVEHost() pveHost {
	return pveHost{
		run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		readFile: os.ReadFile,
		exists:   func(p string) bool { _, err := os.Stat(p); return err == nil },
		hostname: os.Hostname,
		tailscale: func() string {
			out, err := exec.Command("tailscale", "status", "--json", "--peers=false").Output()
			if err != nil {
				return ""
			}
			var st struct{ Self struct{ DNSName string } }
			if json.Unmarshal(out, &st) != nil {
				return ""
			}
			return strings.TrimSuffix(st.Self.DNSName, ".")
		},
	}
}

var (
	pvecmNodesRe = regexp.MustCompile(`(?m)^\s*Nodes:\s+(\d+)`)
	tokenNameRe  = regexp.MustCompile(`[^a-z0-9-]+`)
)

// errSkipProxmox: the Proxmox part does not apply here; the reason is printed and the agent installs anyway.
type errSkipProxmox struct{ why string }

func (e errSkipProxmox) Error() string { return e.why }

// pveTokenName is the token's name for this node: panel-<node>, lower case (a re-pair replaces the same token).
func pveTokenName(node string) string {
	n := strings.Trim(tokenNameRe.ReplaceAllString(strings.ToLower(node), "-"), "-")
	if n == "" {
		n = "node"
	}
	if len(n) > 40 {
		n = n[:40]
	}
	return "panel-" + n
}

// proxmoxGrant makes (or remakes) the panel's read-only token and returns what the panel needs. A skip (not a
// Proxmox VE node, a cluster) is an errSkipProxmox.
func proxmoxGrant(h pveHost, out io.Writer) (*enroll.ProxmoxGrant, error) {
	pveum := ""
	for _, p := range []string{"/usr/sbin/pveum", "/usr/bin/pveum"} {
		if h.exists(p) {
			pveum = p
			break
		}
	}
	if pveum == "" {
		return nil, errSkipProxmox{"this is not a Proxmox VE node (no pveum): skipped the Proxmox part"}
	}
	if h.exists(pveCorosync) {
		st, _ := h.run("pvecm", "status")
		if m := pvecmNodesRe.FindSubmatch(st); m != nil {
			if n, _ := strconv.Atoi(string(m[1])); n > 1 {
				return nil, errSkipProxmox{fmt.Sprintf("this node is in a cluster of %d nodes: adding clusters from the panel is not supported yet "+
					"(add the cluster under proxmox: in the panel's config.yaml); skipped the Proxmox part", n)}
			}
		}
	}
	host, err := h.hostname()
	if err != nil {
		return nil, err
	}
	node := strings.SplitN(host, ".", 2)[0]
	if o, err := h.run(pveum, "user", "add", pveUser, "--comment", "Fairy panel, read-only"); err != nil && !strings.Contains(string(o), "already exists") {
		return nil, fmt.Errorf("pveum user add %s: %s", pveUser, strings.TrimSpace(string(o)))
	}
	if o, err := h.run(pveum, "aclmod", "/", "--users", pveUser, "--roles", "PVEAuditor"); err != nil {
		return nil, fmt.Errorf("pveum aclmod: %s", strings.TrimSpace(string(o)))
	}
	name := pveTokenName(node)
	if o, err := h.run(pveum, "user", "token", "list", pveUser, "--output-format", "json"); err == nil {
		var list []struct {
			TokenID string `json:"tokenid"`
		}
		if json.Unmarshal(o, &list) == nil && slices.ContainsFunc(list, func(t struct {
			TokenID string `json:"tokenid"`
		}) bool {
			return t.TokenID == name
		}) {
			if o, err := h.run(pveum, "user", "token", "remove", pveUser, name); err != nil {
				return nil, fmt.Errorf("pveum user token remove %s!%s: %s", pveUser, name, strings.TrimSpace(string(o)))
			}
			fmt.Fprintf(out, "proxmox: replaced the old token %s!%s\n", pveUser, name)
		}
	}
	o, err := h.run(pveum, "user", "token", "add", pveUser, name, "--privsep", "0", "--comment", "Fairy panel (read-only)", "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("pveum user token add: %s", firstLine(string(o)))
	}
	var tok struct {
		FullTokenID string `json:"full-tokenid"`
		Value       string `json:"value"`
	}
	if err := json.Unmarshal(o, &tok); err != nil || tok.Value == "" {
		return nil, errors.New("pveum user token add: no token in its answer")
	}
	if tok.FullTokenID == "" {
		tok.FullTokenID = pveUser + "!" + name
	}
	g := &enroll.ProxmoxGrant{TokenID: tok.FullTokenID, TokenSecret: tok.Value, Node: node, ServerName: node}
	if ts := h.tailscale(); ts != "" {
		g.URL = "https://" + ts + ":8006"
	}
	// The certificate the panel will see: Proxmox's own (signed by the node's CA, issued for the node's name),
	// unless a custom one is installed.
	if h.exists(pveProxyCert) {
		leaf, err := readCert(h, pveProxyCert)
		if err != nil {
			return nil, err
		}
		if len(leaf.DNSNames) > 0 {
			g.ServerName = leaf.DNSNames[0]
			for _, n := range leaf.DNSNames {
				if g.URL != "" && strings.EqualFold(n, strings.TrimSuffix(strings.TrimPrefix(g.URL, "https://"), ":8006")) {
					g.ServerName = n
				}
			}
		}
		fmt.Fprintf(out, "proxmox: a custom certificate is installed (%s): the panel checks it against the usual public CAs for %s\n", pveProxyCert, g.ServerName)
	} else {
		ca, err := h.readFile(pveRootCA)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", pveRootCA, err)
		}
		g.CAPEM = string(ca)
		if leaf, err := readCert(h, pveNodeCert); err == nil && !slices.ContainsFunc(leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, node) }) {
			fmt.Fprintf(out, "proxmox: WARNING: the node's certificate is not issued for %q (it lists %s); renew it with `pvecm updatecerts --force`, "+
				"then `systemctl restart pveproxy`\n", node, strings.Join(leaf.DNSNames, ", "))
		}
	}
	fmt.Fprintf(out, "proxmox: read-only token %s made for the panel (role PVEAuditor; the secret goes to the panel once, at pairing)\n", g.TokenID)
	return g, nil
}

func readCert(h pveHost, path string) (*x509.Certificate, error) {
	b, err := h.readFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New(path + ": no certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
