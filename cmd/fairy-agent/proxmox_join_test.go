package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

const fakeSecret = "0b7c4e2a-1111-2222-3333-444455556666"

func certPEM(t *testing.T, dns ...string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: dns[0]}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fakePVE is a Proxmox VE node as pveum / pvecm answer (recorded calls, scripted answers).
type fakePVE struct {
	calls     []string
	files     map[string][]byte
	userThere bool
	tokens    []string
	nodes     int
	tsName    string
}

func (f *fakePVE) host() pveHost {
	return pveHost{
		run: func(name string, args ...string) ([]byte, error) {
			line := filepath.Base(name) + " " + strings.Join(args, " ")
			f.calls = append(f.calls, line)
			fail := errors.New("exit status 255")
			switch {
			case line == "pvecm status":
				return []byte(fmt.Sprintf("Cluster information\n-------------------\nName:             homelab\n\nVotequorum information\n----------------------\nNodes:            %d\n", f.nodes)), nil
			case strings.HasPrefix(line, "pveum user add"):
				if f.userThere {
					return []byte("create user failed: user 'fairy@pve' already exists\n"), fail
				}
				f.userThere = true
				return nil, nil
			case strings.HasPrefix(line, "pveum aclmod"):
				return nil, nil
			case strings.HasPrefix(line, "pveum user token list"):
				var parts []string
				for _, t := range f.tokens {
					parts = append(parts, fmt.Sprintf(`{"tokenid":%q,"privsep":0,"expire":0}`, t))
				}
				return []byte("[" + strings.Join(parts, ",") + "]"), nil
			case strings.HasPrefix(line, "pveum user token remove"):
				f.tokens = nil
				return nil, nil
			case strings.HasPrefix(line, "pveum user token add"):
				name := strings.Fields(line)[5]
				f.tokens = append(f.tokens, name)
				return []byte(fmt.Sprintf(`{"full-tokenid":"fairy@pve!%s","info":{"privsep":"0","comment":"Fairy panel (read-only)"},"value":%q}`, name, fakeSecret)), nil
			}
			return []byte("unexpected " + line), fail
		},
		readFile: func(p string) ([]byte, error) {
			if b, ok := f.files[p]; ok {
				return b, nil
			}
			return nil, os.ErrNotExist
		},
		exists: func(p string) bool {
			if p == "/usr/sbin/pveum" {
				return f.files != nil
			}
			_, ok := f.files[p]
			return ok
		},
		hostname:  func() (string, error) { return "asus-i7.lan", nil },
		tailscale: func() string { return f.tsName },
	}
}

func TestProxmoxGrant(t *testing.T) {
	ca := certPEM(t, "Proxmox Virtual Environment")
	f := &fakePVE{files: map[string][]byte{pveRootCA: ca, pveNodeCert: certPEM(t, "asus-i7", "asus-i7.lan", "localhost")},
		tsName: "asus-i7.straws-tailnet.ts.net"}
	var out bytes.Buffer
	g, err := proxmoxGrant(f.host(), &out)
	if err != nil {
		t.Fatal(err)
	}
	if g.TokenID != "fairy@pve!panel-asus-i7" || g.TokenSecret != fakeSecret || g.Node != "asus-i7" || g.ServerName != "asus-i7" ||
		g.URL != "https://asus-i7.straws-tailnet.ts.net:8006" || g.CAPEM != string(ca) {
		t.Fatalf("%+v", g)
	}
	want := []string{"pveum user add fairy@pve --comment Fairy panel, read-only", "pveum aclmod / --users fairy@pve --roles PVEAuditor",
		"pveum user token list fairy@pve --output-format json",
		"pveum user token add fairy@pve panel-asus-i7 --privsep 0 --comment Fairy panel (read-only) --output-format json"}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(f.calls, "\n"))
	}
	if strings.Contains(out.String(), fakeSecret) || strings.Contains(out.String(), "WARNING") {
		t.Fatal(out.String())
	}
	// again (Re-pair): the user exists, the same token is removed and made again; nothing else is touched
	f.calls, out = nil, bytes.Buffer{}
	if _, err := proxmoxGrant(f.host(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "pveum user token remove fairy@pve panel-asus-i7") || !strings.Contains(out.String(), "replaced") {
		t.Fatal(f.calls, out.String())
	}
	// a certificate not issued for the node's name: a clear warning with the fix
	f.files[pveNodeCert] = certPEM(t, "pve", "localhost")
	out.Reset()
	if _, err := proxmoxGrant(f.host(), &out); err != nil || !strings.Contains(out.String(), "pvecm updatecerts --force") {
		t.Fatal(err, out.String())
	}
	// a custom (ACME) certificate: no CA, checked for its own name
	f.files[pveProxyCert] = certPEM(t, "asus-i7.example.org", "asus-i7.straws-tailnet.ts.net")
	g, err = proxmoxGrant(f.host(), &out)
	if err != nil || g.CAPEM != "" || g.ServerName != "asus-i7.straws-tailnet.ts.net" {
		t.Fatalf("%+v %v", g, err)
	}
}

func TestProxmoxGrantSkips(t *testing.T) {
	var out bytes.Buffer
	var skip errSkipProxmox
	if _, err := proxmoxGrant((&fakePVE{}).host(), &out); !errors.As(err, &skip) || !strings.Contains(skip.why, "not a Proxmox VE node") {
		t.Fatal(err)
	}
	f := &fakePVE{files: map[string][]byte{pveCorosync: []byte("totem {}"), pveRootCA: []byte("x")}, nodes: 3}
	if _, err := proxmoxGrant(f.host(), &out); !errors.As(err, &skip) || !strings.Contains(skip.why, "cluster of 3 nodes") {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.calls, ","), "pveum") {
		t.Fatal("a cluster must not get a token", f.calls)
	}
	f.nodes = 1 // a "cluster" of one node is a standalone node
	if _, err := proxmoxGrant(f.host(), &out); err != nil {
		t.Fatal(err)
	}
	if pveTokenName("LAB Node_01") != "panel-lab-node-01" {
		t.Fatal(pveTokenName("LAB Node_01"))
	}
}

// join --proxmox stores the grant in the pairing state (0600), prints no secret.
func TestJoinProxmoxStoresTheGrant(t *testing.T) {
	if !isAdmin() {
		t.Skip("join needs root / Administrator")
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir, state := t.TempDir(), t.TempDir()
	code, _ := enroll.NewCode()
	f := &fakePVE{files: map[string][]byte{pveRootCA: certPEM(t, "Proxmox Virtual Environment"), pveNodeCert: certPEM(t, "asus-i7")}}
	h := f.host()
	o, err := parseJoin([]string{"--code", code, "--panel", "100.64.0.10", "--config", filepath.Join(dir, "config.yaml"),
		"--state-dir", state, "--proxmox"}, os.Stderr)
	if err != nil || !o.proxmox {
		t.Fatal(err)
	}
	o.pve = &h
	var out bytes.Buffer
	if err := join(o, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), fakeSecret) || !strings.Contains(out.String(), "fairy@pve!panel-asus-i7") {
		t.Fatal(out.String())
	}
	st, err := enroll.ReadState(filepath.Join(state, "pairing.json"))
	if err != nil || st.Proxmox == nil || st.Proxmox.TokenSecret != fakeSecret {
		t.Fatalf("%+v %v", st, err)
	}
	if fi, _ := os.Stat(filepath.Join(state, "pairing.json")); fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
}
