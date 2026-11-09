package collect

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// A small SDDL reader for the tests (owner and DACL; the part of SDDL that Get-Acl's .Sddl shows for files), so the
// fixtures below are written the way Windows prints real permissions. x/sys/windows only builds for Windows.

var sddlSIDs = map[string]string{
	"SY": sidSystem, "BA": sidAdministrators, "BU": "S-1-5-32-545", "AU": "S-1-5-11", "WD": "S-1-1-0",
	"CO": "S-1-3-0", "CG": "S-1-3-1", "OW": "S-1-3-4", "AC": "S-1-15-2-1", "IU": "S-1-5-4", "PU": "S-1-5-32-547",
	"LS": "S-1-5-19", "NS": "S-1-5-20",
}

var sddlRights = map[string]uint32{
	"GA": accessGenericAll, "GR": accessGenericRead, "GW": accessGenericWrite, "GX": accessGenericExec,
	"RC": 0x20000, "SD": accessDelete, "WD": accessWriteDAC, "WO": accessWriteOwner,
	"CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
	"FA": fileAllAccess, "FR": fileGenericRead, "FW": fileGenericWrite, "FX": fileGenericExec,
}

var sddlFlags = map[string]uint8{"OI": 0x1, "CI": 0x2, "NP": 0x4, "IO": 0x8, "ID": 0x10}

var sddlTypes = map[string]uint8{"A": 0x0, "D": 0x1, "OA": 0x5, "OD": 0x6, "XA": 0x9, "XD": 0xa}

type sddlACE struct {
	typ, flags uint8
	mask       uint32
	sid        string
}

// parseSDDL returns the owner SID, whether there is no DACL (D:NO_ACCESS_CONTROL) and the DACL's entries.
func parseSDDL(t *testing.T, s string) (owner string, null bool, aces []sddlACE) {
	t.Helper()
	// split into O:, G:, D:, S: parts: a part ends where the next tag starts outside parentheses
	parts := map[byte]string{}
	for len(s) >= 2 && s[1] == ':' {
		tag, depth, end := s[0], 0, len(s)
		for j := 2; j < len(s); j++ {
			switch s[j] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 && j+1 < len(s) && s[j+1] == ':' && strings.IndexByte("OGDS", s[j]) >= 0 {
				end = j
				break
			}
		}
		parts[tag], s = s[2:end], s[end:]
	}
	if s != "" {
		t.Fatalf("SDDL: unexpected %q", s)
	}
	owner = sddlSID(t, parts['O'])
	d, ok := parts['D']
	switch {
	case !ok || strings.HasPrefix(d, "NO_ACCESS_CONTROL"):
		return owner, true, nil
	case !strings.Contains(d, "("):
		return owner, false, nil // flags only: an empty DACL
	}
	for _, e := range strings.Split(strings.TrimSuffix(d[strings.Index(d, "(")+1:], ")"), ")(") {
		aces = append(aces, sddlEntry(t, e))
	}
	return owner, false, aces
}

func sddlSID(t *testing.T, s string) string {
	t.Helper()
	if strings.HasPrefix(s, "S-1-") {
		return s
	}
	if v, ok := sddlSIDs[s]; ok {
		return v
	}
	t.Fatalf("SDDL: unknown SID %q", s)
	return ""
}

func sddlEntry(t *testing.T, e string) sddlACE {
	t.Helper()
	f := strings.Split(e, ";")
	if len(f) < 6 {
		t.Fatalf("SDDL: bad entry %q", e)
	}
	var a sddlACE
	typ, ok := sddlTypes[f[0]]
	if !ok {
		t.Fatalf("SDDL: unknown entry type %q", f[0])
	}
	a.typ = typ
	for fl := f[1]; fl != ""; fl = fl[2:] {
		v, ok := sddlFlags[fl[:2]]
		if !ok {
			t.Fatalf("SDDL: unknown flag in %q", f[1])
		}
		a.flags |= v
	}
	if strings.HasPrefix(f[2], "0x") {
		v, err := strconv.ParseUint(f[2][2:], 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		a.mask = uint32(v)
	} else {
		for r := f[2]; r != ""; r = r[2:] {
			v, ok := sddlRights[r[:2]]
			if !ok {
				t.Fatalf("SDDL: unknown right in %q", f[2])
			}
			a.mask |= v
		}
	}
	a.sid = sddlSID(t, f[5])
	return a
}

// binarySID encodes S-1-a-b-c... as Windows stores it.
func binarySID(t *testing.T, s string) []byte {
	t.Helper()
	p := strings.Split(s, "-")
	if len(p) < 3 || p[0] != "S" || p[1] != "1" {
		t.Fatalf("bad SID %q", s)
	}
	auth, err := strconv.ParseUint(p[2], 10, 48)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{1, byte(len(p) - 3), 0, 0, 0, 0, 0, 0}
	for i := 0; i < 6; i++ {
		b[7-i] = byte(auth >> (8 * i))
	}
	for _, sub := range p[3:] {
		v, err := strconv.ParseUint(sub, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(v))
	}
	return b
}

// binaryACL encodes the entries as a Windows ACL (revision 2; object entries without GUIDs, or with an
// object-type GUID when objGUID is set, to exercise ParseDACL's offsets).
func binaryACL(t *testing.T, aces []sddlACE, objGUID bool) []byte {
	t.Helper()
	var body []byte
	for _, a := range aces {
		e := []byte{a.typ, a.flags, 0, 0}
		e = binary.LittleEndian.AppendUint32(e, a.mask)
		if a.typ == 0x5 || a.typ == 0x6 {
			if objGUID {
				e = binary.LittleEndian.AppendUint32(e, 1)
				e = append(e, make([]byte, 16)...)
			} else {
				e = binary.LittleEndian.AppendUint32(e, 0)
			}
		}
		e = append(e, binarySID(t, a.sid)...)
		binary.LittleEndian.PutUint16(e[2:4], uint16(len(e)))
		body = append(body, e...)
	}
	h := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(h[2:4], uint16(8+len(body)))
	binary.LittleEndian.PutUint16(h[4:6], uint16(len(aces)))
	return append(h, body...)
}

// sddlCheck runs the real path: SDDL -> binary DACL -> ParseDACL -> CheckWindowsACL.
func sddlCheck(t *testing.T, path string, kind int, sddl string) error {
	t.Helper()
	owner, null, aces := parseSDDL(t, sddl)
	parsed, err := ParseDACL(binaryACL(t, aces, false))
	if err != nil {
		t.Fatalf("%s: ParseDACL: %v", path, err)
	}
	if len(parsed) != len(aces) {
		t.Fatalf("%s: %d entries parsed, want %d", path, len(parsed), len(aces))
	}
	for i, a := range aces {
		p := parsed[i]
		if p.SID != a.sid || p.Mask != a.mask || p.Flags != a.flags {
			t.Fatalf("%s: entry %d parsed as %+v, want %+v", path, i, p, a)
		}
	}
	return CheckWindowsACL(path, kind, owner, null, parsed)
}

func TestParseDACL(t *testing.T) {
	aces := []sddlACE{
		{0x0, 0x13, fileAllAccess, sidSystem},
		{0x1, 0x0, accessWriteDAC, "S-1-5-32-545"},
		{0x5, 0x0, 0x1301bf, "S-1-5-21-1-2-3-1001"},
		{0x9, 0x8, accessGenericAll, "S-1-3-0"},
		{0x0, 0x0, 0x1200a9, sidTrustedInstaller},
	}
	for _, guid := range []bool{false, true} {
		got, err := ParseDACL(binaryACL(t, aces, guid))
		if err != nil {
			t.Fatal(err)
		}
		want := []int{ACEAllow, ACEDeny, ACEAllow, ACEAllow, ACEAllow}
		for i, a := range aces {
			if got[i].SID != a.sid || got[i].Mask != a.mask || got[i].Flags != a.flags || got[i].Kind != want[i] {
				t.Errorf("guid=%v entry %d: %+v, want %+v", guid, i, got[i], a)
			}
		}
	}
	// a type the check does not know (compound / audit / label) counts as an unknown principal's allow entry
	b := binaryACL(t, []sddlACE{{0x0, 0, 0x1200a9, sidSystem}}, false)
	b[8] = 0x11
	if got, err := ParseDACL(b); err != nil || got[0].Kind != ACEOther || got[0].SID != "" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := CheckWindowsACL("x", ObjAncestor, sidSystem, false, []ACE{{Kind: ACEOther, Mask: accessDelete}}); err == nil {
		t.Fatal("unknown entry with DELETE accepted")
	}
	// truncated and inconsistent ACLs are refused, not read past their end
	good := binaryACL(t, aces, true)
	for _, bad := range [][]byte{good[:7], good[:len(good)-1], append(append([]byte{}, good[:8]...), 0, 0, 4, 0)} {
		if _, err := ParseDACL(bad); err == nil {
			t.Errorf("bad ACL % x accepted", bad)
		}
	}
	if s := sidString(binarySID(t, sidTrustedInstaller)); s != sidTrustedInstaller {
		t.Fatal(s)
	}
	if s := sidString([]byte{1, 0, 0x10, 0, 0, 0, 0, 0}); s != "S-1-0x100000000000" {
		t.Fatal(s)
	}
}
