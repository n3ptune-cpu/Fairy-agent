package main

// `fairy-agent helper-trust set | show | clear`: the approval trust of this machine, changed where only an
// administrator can change it. The panel can set the trust once, while there is none (POST /approval/trust);
// everything after that (another key after a key rotation at Pocket ID, other users, the fan window, the
// shutdown-after-boot setting, switching the check off) is done here and nowhere else.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

const helperTrustUsage = `fairy-agent helper-trust: which Pocket ID this machine believes when an action needs a passkey approval

  fairy-agent helper-trust show  [--config PATH]
  fairy-agent helper-trust set   [--config PATH] [--issuer URL] [--client-id ID] [--user SUB]...
                                 [--fetch-keys | --jwks FILE] [--keep-old-keys]
                                 [--fan-window SECONDS] [--boot-shutdown SECONDS] [--from FILE] [--yes]
  fairy-agent helper-trust clear [--config PATH] [--yes]

set (root / Administrator) writes the trust file. What is not given stays as it is in the existing file.
  --issuer URL          Pocket ID's address, exactly as in its tokens ("iss"), https://
  --client-id ID        the client id of the Pocket ID client "Fairy PC actions"
  --user SUB            a user who may approve (the user's id in Pocket ID, the "sub" of the token); repeat it
                        for more users; the users given replace the list
  --fetch-keys          fetch the signing keys from the issuer now (https, the issuer's own jwks_uri). Done
                        without being asked when there is no key yet. After a key rotation at Pocket ID: run
                        "set --fetch-keys" again
  --jwks FILE           take the signing keys from a JWKS file instead of the network
  --keep-old-keys       keep the keys that are pinned now next to the new ones (at most 4 in all)
  --fan-window N        seconds in which further fan changes need no new approval after an approved one
                        (default 30, 0 = off, at most 60)
  --boot-shutdown N     accept ONE shutdown without approval while the machine has been up for less than N
                        seconds (default 0 = off, at most 900): for machines that are switched on only to be
                        updated and switched off again
  --from FILE           start from a complete trust file instead of the existing one
  --yes                 do not ask before writing
show prints the trust file and whether it can be used. clear removes it: nothing needs an approval any more,
and the panel can set the trust again (once). Whoever holds the control token can do that first-time set,
with an issuer and users of his own: do not leave a machine at "off" longer than needed.

The panel's first-time set is accepted only with a passkey approval that proves the values work. set, typed
here, proves nothing: it writes what it is given. A wrong issuer spelling, client id or user id, or a clock
that is off, then shows at the first approval ("approval refused"). So approve one action from the panel
while you are still at the machine; clear undoes the set.
Linux: run it as root. In the agent's own state folder it works as the agent's user (see AGENT.md).
`

// Seams for the tests.
var (
	trustFiles   = func(cfg *agent.Config) approval.Files { return agent.ApprovalAdminFiles(cfg) }
	trustIsAdmin = isAdmin
	trustBecome  = trustBecomeOwner
	trustNow     = time.Now
	// trustHelper says what runs next to the trust file on this machine (trustEffect): the Windows helper's
	// service state and, when it runs, its status answer. Other systems have no helper.
	trustHelper     = helperForTrust
	trustHTTPClient = func() *http.Client {
		return &http.Client{Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("the issuer answered with a redirect") }}
	}
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func helperTrustCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "set" && args[0] != "show" && args[0] != "clear") {
		fmt.Fprint(stderr, helperTrustUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("helper-trust "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, helperTrustUsage) }
	cfgPath := fs.String("config", agent.DefaultConfigPath(), "")
	issuer := fs.String("issuer", "", "")
	clientID := fs.String("client-id", "", "")
	var users multiFlag
	fs.Var(&users, "user", "")
	fetch := fs.Bool("fetch-keys", false, "")
	jwks := fs.String("jwks", "", "")
	keepOld := fs.Bool("keep-old-keys", false, "")
	fanWindow := fs.Int("fan-window", -1, "")
	bootShutdown := fs.Int("boot-shutdown", -1, "")
	from := fs.String("from", "", "")
	yes := fs.Bool("yes", false, "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		if err == nil {
			fmt.Fprint(stderr, helperTrustUsage)
		}
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "fairy-agent helper-trust "+sub+":", err)
		return 1
	}
	// Windows: config.yaml says where the data folder is; one that someone else could have written is not
	// followed (the same check as the other commands an administrator types)
	if err := adminDataDirTrusted(*cfgPath); err != nil {
		return fail(err)
	}
	cfg, err := agent.Load(*cfgPath)
	if err != nil {
		return fail(fmt.Errorf("config problem: %w", err))
	}
	files := trustFiles(cfg)
	if sub != "show" && !trustIsAdmin() {
		return fail(errors.New("run it as root / in an Administrator PowerShell"))
	}
	// what set reads from files the administrator names is read now, as the administrator: from here on (not
	// Windows) the file work may be done as the owner of the agent's state folder (trust_unix.go)
	var fromData, jwksData []byte
	if sub == "set" && *from != "" {
		if fromData, err = os.ReadFile(*from); err != nil {
			return fail(err)
		}
	}
	if sub == "set" && *jwks != "" && !*fetch {
		if jwksData, err = os.ReadFile(*jwks); err != nil {
			return fail(err)
		}
	}
	as, err := trustBecome(files.Path)
	if err != nil {
		return fail(err)
	}
	state, old, _, loadErr := files.Load()
	switch sub {
	case "show":
		fmt.Fprintln(stdout, "trust file:     ", files.Path)
		if as != "" {
			fmt.Fprintln(stdout, as)
		}
		printTrust(stdout, state, old, loadErr)
		return 0
	case "clear":
		if state == api.ApprovalOff {
			fmt.Fprintln(stdout, "there is no trust file ("+files.Path+"): nothing needs an approval, and the panel can set the trust (once)")
			return 0
		}
		fmt.Fprintln(stdout, "trust file:     ", files.Path)
		printTrust(stdout, state, old, loadErr)
		if !*yes && !confirm(stdin, stdout, "Remove it? Fan, power and update requests will then need NO approval, and the panel can set the trust again.") {
			fmt.Fprintln(stdout, "nothing changed")
			return 1
		}
		if err := files.Remove(); err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, "removed. Approval is off (in effect within 5 seconds); the panel can now set trust again (once).")
		fmt.Fprintln(stdout, "  That first-time set is open to whoever holds the control token, with values of his own. Do not leave")
		fmt.Fprintln(stdout, "  this machine at \"off\" longer than needed: let your panel set the trust now, or: fairy-agent helper-trust set ...")
		return 0
	}

	// set
	var t approval.Trust
	if old != nil {
		t = approval.Trust{Issuer: old.Issuer, ClientID: old.ClientID, Keys: old.Keys, Users: old.Users,
			FanWindowS: old.FanWindowS, BootShutdownS: old.BootShutdownS}
	} else if state == api.ApprovalBroken {
		fmt.Fprintln(stdout, "note: the existing trust file cannot be used and will be replaced:", loadErr)
	}
	if *from != "" {
		ft, err := approval.ParseTrust(fromData)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", *from, err))
		}
		t = approval.Trust{Issuer: ft.Issuer, ClientID: ft.ClientID, Keys: ft.Keys, Users: ft.Users,
			FanWindowS: ft.FanWindowS, BootShutdownS: ft.BootShutdownS}
	}
	oldKeys := t.Keys
	if *issuer != "" {
		t.Issuer = *issuer
	}
	if *clientID != "" {
		t.ClientID = *clientID
	}
	if len(users) > 0 {
		t.Users = []string(users)
	}
	if *fanWindow >= 0 {
		t.FanWindowS = fanWindow
	}
	if *bootShutdown >= 0 {
		t.BootShutdownS = *bootShutdown
	}
	var missing []string
	if t.Issuer == "" {
		missing = append(missing, "--issuer")
	}
	if t.ClientID == "" {
		missing = append(missing, "--client-id")
	}
	if len(t.Users) == 0 {
		missing = append(missing, "--user")
	}
	if len(missing) > 0 {
		return fail(errors.New("still needed: " + strings.Join(missing, ", ")))
	}
	source := "kept from the existing trust file"
	if *from != "" {
		source = "from " + *from
	}
	var notes []string
	switch {
	case *jwks != "" && *fetch:
		return fail(errors.New("--fetch-keys and --jwks exclude each other"))
	case *jwks != "":
		if t.Keys, notes, err = keysFromJWKS(jwksData); err != nil {
			return fail(fmt.Errorf("%s: %w", *jwks, err))
		}
		source = "from " + *jwks
	case *fetch || len(t.Keys) == 0:
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var uri string
		var issuerTime time.Time
		if t.Keys, notes, uri, issuerTime, err = fetchIssuerKeys(ctx, trustHTTPClient(), t.Issuer); err != nil {
			return fail(fmt.Errorf("fetching the issuer's keys: %w (or give them in a file: --jwks FILE)", err))
		}
		source = "fetched just now from " + uri
		if n := clockNote(issuerTime, trustNow()); n != "" {
			notes = append(notes, n)
		}
	}
	if *keepOld {
		for _, k := range oldKeys {
			if !hasKid(t.Keys, k.Kid) {
				t.Keys = append(t.Keys, k)
			}
		}
	}
	if t.FanWindowS == nil {
		w := approval.DefaultFanWindowS
		t.FanWindowS = &w
	}
	t.SetBy, t.SetAt = "admin", time.Now().UTC().Format(time.RFC3339)
	nt, err := approval.NewTrust(t)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintln(stdout, "trust file:     ", files.Path)
	fmt.Fprintln(stdout, "to be written:")
	printTrust(stdout, api.ApprovalRequired, nt, nil)
	fmt.Fprintln(stdout, "signing keys:   ", source)
	for _, n := range notes {
		fmt.Fprintln(stdout, "note:", n)
	}
	if !*yes && !confirm(stdin, stdout, "Write this? Compare the key thumbprints with Pocket ID's first.") {
		fmt.Fprintln(stdout, "nothing changed")
		return 1
	}
	if err := files.Replace(nt); err != nil {
		return fail(err)
	}
	if st, _, _, err := files.Load(); st != api.ApprovalRequired {
		return fail(fmt.Errorf("the file was written but cannot be used, so everything that needs an approval is refused until this is repaired: %v", err))
	}
	fmt.Fprintln(stdout, "written. From now on only this command changes it (the panel cannot).")
	for _, l := range trustEffect(trustHelper()) {
		fmt.Fprintln(stdout, l)
	}
	fmt.Fprintln(stdout, "NOT PROVEN: nothing has checked that Pocket ID issues approvals that fit these values (the panel's own")
	fmt.Fprintln(stdout, "  first-time set is accepted only with such a proof; this command writes what it is given). A wrong issuer")
	fmt.Fprintln(stdout, "  spelling, client id or user id, or a clock that is more than 60 s off, shows at the first approval as")
	fmt.Fprintln(stdout, "  \"approval refused\". Approve one action from the panel now, while you are at this machine.")
	fmt.Fprintln(stdout, "  To undo: fairy-agent helper-trust clear")
	return 0
}

// Helper states for trustEffect, beyond the api.Helper... ones.
const (
	trustNoHelperHere = "none"     // not Windows: the agent is the one that checks
	trustHelperAsked  = "answered" // the helper runs and answered a status request
)

// trustEffect says, after helper-trust set has written the trust file, when what it asks for is really in
// effect, from what runs on this machine: state is trustNoHelperHere, api.HelperNotInstalled, another service
// state of the helper, or trustHelperAsked with the helper's status answer in statusData; err is why the
// helper could not be asked. The command prints what is true, not what is usual: a helper from before passkey
// approvals that is still running (an update that did not restart it) reads no trust file at all.
func trustEffect(state string, statusData []byte, err error) []string {
	const reads = "reads the trust file again every 5 seconds"
	// what "within 5 seconds" leaves open, said with it (audit 5, r1-a1-05)
	const until = "  Until then what was in effect before still counts: no check if there was no trust, and a user or key you just removed can still approve."
	switch {
	case state == trustNoHelperHere:
		return []string{"In effect within 5 seconds, if the fairy-agent service runs this version: it " + reads + ".", until,
			"  An older fairy-agent (from before passkey approvals) ignores the file: `fairy-agent version`; if it is older, install this version."}
	case err != nil:
		return []string{"NOT KNOWN whether it is in effect: the helper could not be asked (" + clipText(err.Error(), 200) + ").",
			"  Check: `fairy-agent helper-status` must show `pipe protocol:   2` and `approval:        required`."}
	case state == api.HelperNotInstalled:
		return []string{"In effect within 5 seconds for what the agent carries out itself: no fairy-agent-helper is installed, the agent " + reads + ".", until}
	case state != trustHelperAsked:
		return []string{"The fairy-agent-helper service is not running (" + state + "): it reads the trust file when it starts.",
			"  Until then nothing that goes through the helper runs at all, and the agent refuses updates."}
	}
	var sd struct {
		Proto    int                 `json:"proto"`
		Approval *api.ApprovalStatus `json:"approval"`
	}
	if json.Unmarshal(statusData, &sd) != nil || sd.Proto < 2 || sd.Approval == nil {
		return []string{"NOT IN EFFECT IN THE HELPER YET: the fairy-agent-helper that is running is from before passkey approvals",
			"  (pipe protocol 1, the program from before the last update). It reads no trust file and checks nothing.",
			"  Until it is restarted, the agent refuses the fan, power and update requests that go through it",
			"  (503 approval_unavailable), and the panel's challenge is answered 409 helper_too_old.",
			"  Restart it now: Restart-Service fairy-agent-helper   (then: fairy-agent helper-status)"}
	}
	return []string{"In effect within 5 seconds: the running helper (pipe protocol " + strconv.Itoa(sd.Proto) + ") " + reads + ", and so does the agent.", until}
}

// clockNote says so when this machine's clock (now) and the issuer's (the Date of its answer) are far enough
// apart to matter: an approval is refused when they differ by more than approval.ClockAllowance. "" when they
// agree or the issuer's time is not known.
func clockNote(issuer, now time.Time) string {
	if issuer.IsZero() {
		return ""
	}
	d := now.Sub(issuer)
	if d < 0 {
		d = -d
	}
	if d <= approval.ClockAllowance*3/4 {
		return ""
	}
	return fmt.Sprintf("THE CLOCK: this machine's clock and the issuer's differ by about %d s. Approvals are refused when they differ by more than %d s: set this machine's clock first",
		int(d/time.Second), int(approval.ClockAllowance/time.Second))
}

func hasKid(keys []api.TrustKey, kid string) bool {
	for _, k := range keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// confirm asks a yes / no question on stdout and reads the answer from stdin.
func confirm(stdin io.Reader, stdout io.Writer, question string) bool {
	fmt.Fprint(stdout, question+" [yes/no] ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "yes" || a == "y"
}

// printTrust prints the state of the trust file and, when it can be read, what it holds (helper-trust show /
// set / clear: the administrator also sees who may approve).
func printTrust(w io.Writer, state string, t *approval.Trust, loadErr error) {
	switch state {
	case api.ApprovalOff:
		fmt.Fprintln(w, "approval:        off (no trust file: nothing needs an approval; the panel can set the trust once)")
		return
	case api.ApprovalBroken:
		fmt.Fprintln(w, "approval:        BROKEN: the trust file cannot be used, so fan, power and update requests are refused")
		fmt.Fprintln(w, "reason:         ", loadErr)
		fmt.Fprintln(w, "repair:          fairy-agent helper-trust set ...   or   fairy-agent helper-trust clear")
		return
	}
	for _, l := range approvalLines(t.Status()) {
		fmt.Fprintln(w, l)
	}
	for _, u := range t.Users {
		fmt.Fprintln(w, "  may approve:   ", u)
	}
}

// approvalLines is the approval block as lines for people (helper-status, helper-trust). No secrets: the
// issuer, the client id, key ids and thumbprints, and how many users may approve.
func approvalLines(st api.ApprovalStatus) []string {
	by := ""
	switch st.EnforcedBy {
	case api.EnforcedByHelper:
		by = " (checked by the helper)"
	case api.EnforcedByAgent:
		by = " (checked by the agent)"
	}
	switch st.State {
	case api.ApprovalOff:
		return []string{"approval:        off" + by + ": no trust file, nothing needs an approval; the panel can set the trust once"}
	case api.ApprovalRequired:
	default:
		return []string{"approval:        " + st.State + by + ": fan, power and update requests are refused", "reason:          " + st.Error}
	}
	lines := []string{"approval:        required" + by + ": fan changes, shutdown / reboot / sleep and update need a passkey approval",
		"issuer:          " + st.Issuer, "client id:       " + st.ClientID}
	for _, k := range st.Keys {
		lines = append(lines, "pinned key:      kid "+k.Kid+", "+k.Alg+", thumbprint "+k.Thumbprint)
	}
	lines = append(lines, "allowed users:   "+strconv.Itoa(st.Users))
	if st.TrustHash != "" {
		lines = append(lines, "trust hash:      "+st.TrustHash+" (of issuer, client id, keys and users; the panel shows the hash of what it would set)")
	}
	if st.SetBy != "" {
		how := map[string]string{"panel": " (over the network: a first-time set, by whoever held the control token)", "admin": " (on this machine: helper-trust set)"}[st.SetBy]
		lines = append(lines, "set by:          "+st.SetBy+", "+st.SetAt+how)
	}
	fan, boot := "off", "off (every shutdown needs an approval)"
	if st.FanWindowS != nil && *st.FanWindowS > 0 {
		fan = strconv.Itoa(*st.FanWindowS) + " s after an approved fan change, further fan changes need none"
	}
	if st.BootShutdownS != nil && *st.BootShutdownS > 0 {
		boot = "ONE shutdown without approval while the machine has been up for less than " + strconv.Itoa(*st.BootShutdownS) + " s"
	}
	return append(lines, "fan window:      "+fan, "shutdown after boot: "+boot)
}

const maxJWKS = 256 << 10

// keysFromJWKS takes the RSA signing keys out of a JWKS document ({"keys": [...]}) in the pinned form: kty,
// kid, alg RS256, n, e and nothing else. Keys of another kind are left out and named in notes.
func keysFromJWKS(b []byte) (keys []api.TrustKey, notes []string, err error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if len(b) > maxJWKS || json.Unmarshal(b, &doc) != nil {
		return nil, nil, errors.New("not a JWKS document")
	}
	for _, k := range doc.Keys {
		name := fmt.Sprintf("key %q", clipText(k.Kid, 40))
		switch {
		case k.Use != "" && k.Use != "sig":
			notes = append(notes, name+" left out: not a signing key")
			continue
		case k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256"):
			notes = append(notes, fmt.Sprintf("%s left out: %s %s is not supported (only RSA keys for RS256)", name, clipText(k.Kty, 10), clipText(k.Alg, 10)))
			continue
		}
		// some issuers write the modulus with a leading zero byte; the pinned form has none
		if nb, derr := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "=")); derr == nil {
			for len(nb) > 1 && nb[0] == 0 {
				nb = nb[1:]
			}
			k.N = base64.RawURLEncoding.EncodeToString(nb)
		}
		keys = append(keys, api.TrustKey{Kty: "RSA", Kid: k.Kid, Alg: "RS256", N: k.N, E: k.E})
	}
	if len(keys) == 0 {
		return nil, notes, errors.New("no RSA signing key in it (" + strings.Join(notes, "; ") + ")")
	}
	return keys, notes, nil
}

func clipText(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// fetchIssuerKeys reads the issuer's discovery document and its JWKS over https. The document must name the
// same issuer, and its jwks_uri must be https on the issuer's own host; redirects are not followed. at is the
// issuer's clock, from the Date of its last answer (zero: it sent none).
func fetchIssuerKeys(ctx context.Context, c *http.Client, issuer string) (keys []api.TrustKey, notes []string, uri string, at time.Time, err error) {
	keys, notes, uri, date, err := fetchIssuerKeysDate(ctx, c, issuer)
	if err == nil && date != "" {
		at, _ = http.ParseTime(date)
	}
	return keys, notes, uri, at, err
}

func fetchIssuerKeysDate(ctx context.Context, c *http.Client, issuer string) (keys []api.TrustKey, notes []string, uri, date string, err error) {
	iu, err := url.Parse(issuer)
	if err != nil || iu.Scheme != "https" || iu.Host == "" {
		return nil, nil, "", "", errors.New("the issuer must be an https:// URL")
	}
	b, _, err := httpGet(ctx, c, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, nil, "", "", err
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil, nil, "", "", errors.New("the discovery document is not JSON")
	}
	if doc.Issuer != issuer {
		return nil, nil, "", "", fmt.Errorf("the issuer calls itself %q, not %q: use exactly its own spelling for --issuer", clipText(doc.Issuer, 255), issuer)
	}
	ju, err := url.Parse(doc.JWKSURI)
	if err != nil || ju.Scheme != "https" || ju.Host != iu.Host {
		return nil, nil, "", "", fmt.Errorf("the issuer's jwks_uri %q is not https on the issuer's own host", clipText(doc.JWKSURI, 255))
	}
	if b, date, err = httpGet(ctx, c, doc.JWKSURI); err != nil {
		return nil, nil, "", "", err
	}
	keys, notes, err = keysFromJWKS(b)
	return keys, notes, doc.JWKSURI, date, err
}

// httpGet returns the body of a 200 answer and its Date header.
func httpGet(ctx context.Context, c *http.Client, u string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("%s answered %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxJWKS {
		return nil, "", fmt.Errorf("%s: the answer is too large", u)
	}
	return b, resp.Header.Get("Date"), nil
}

// helperApprovalLines is what helper-status prints about approvals from the helper's status answer: whether
// the check is off, required or broken, and what the helper trusts.
func helperApprovalLines(statusData []byte) []string {
	var sd struct {
		Proto    int                 `json:"proto"`
		Approval *api.ApprovalStatus `json:"approval"`
	}
	if json.Unmarshal(statusData, &sd) != nil || sd.Approval == nil {
		return []string{"approval:        this helper is from before passkey approvals (it checks none)"}
	}
	return append([]string{"pipe protocol:   " + strconv.Itoa(sd.Proto)}, approvalLines(*sd.Approval)...)
}
