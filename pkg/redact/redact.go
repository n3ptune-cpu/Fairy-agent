// Package redact removes secrets from process command lines before they leave the agent.
//
// It is best effort. A command line is free text, and nothing can tell every password from every other word:
// the filter knows the common ways of passing a secret (listed at Args) and hides those. A secret passed as a
// plain positional argument of a program it does not know stays visible. Whoever must not see command lines at
// all switches them off (processes.cmdline: false).
package redact

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const mask = "***"

// maxInput is how much of a command line, or of one argument, is looked at. What is kept is far shorter
// (maxLen characters), and the filter's work grows with its input: a line of megabytes (the panel filters what
// agents send it) must not cost more than this much. Whatever lies beyond is dropped, never shown.
const maxInput = 16 << 10

// head cuts s to maxInput bytes (at a character boundary) and marks the cut with an ellipsis.
func head(s string) string {
	if len(s) <= maxInput {
		return s
	}
	i := maxInput
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + "…"
}

// secretWords are the words that mark an option, a variable or a header as holding a secret.
const secretWords = `(?:password|passwd|passphrase|pass|pwd|token|secret|api[-_]?key|apikey|access[-_]?key|private[-_]?key|key|auth|credentials?|bearer|cookie)`

// secretHints are the lower-case pieces every match of secretWords contains (a cheap test before a regexp runs).
var secretHints = []string{"pass", "pwd", "token", "secret", "key", "auth", "credential", "bearer", "cookie"}

var (
	// --password=x, -token=x, --api-key=x (the whole rest of the argument is the value)
	flagEq = regexp.MustCompile(`(?is)^(--?[\w-]*` + secretWords + `[\w-]*)=(.+)$`)
	// --password, -token, --s3-secret-access-key: the next argument is the value
	flagOnly = regexp.MustCompile(`(?i)^--?[\w-]*` + secretWords + `[\w-]*$`)
	// FOO_TOKEN=x as a whole argument (the value may contain blanks)
	envEq = regexp.MustCompile(`(?is)^([\w.-]*` + secretWords + `[\w.-]*)=(.+)$`)
	// password=x, key=x, spring.datasource.password=x somewhere inside an argument
	kvName = regexp.MustCompile(`(?i)\b[\w.-]*` + secretWords + `[\w.-]*=`)
	// the name of the next query parameter: where a value inside a query string ends
	queryNext = regexp.MustCompile(`^&[\w.%\[\]-]+=`)
	// "password":"x" / 'token':'x' (JSON bodies)
	jsonKV = regexp.MustCompile(`(?i)(["']?[\w.-]*` + secretWords + `[\w.-]*["']?:)(["'])[^"']*(["'])`)
	// a header or key name on its own: "Authorization:", "X-Api-Key:", {"password":
	secretName = regexp.MustCompile(`(?i)` + secretWords)
	// scheme://authority
	urlAuthority = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s]*`)
	// /p:x, /password:x (Windows-style options)
	slashOpt = regexp.MustCompile(`(?i)^(/(?:p|pw|pwd|pass|password)):(.+)$`)
	// tokens that are recognisable by their shape wherever they stand
	shapes = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|glpat-[\w-]{20,}|xox[abprs]-[\w-]{10,}|sk-[\w-]{20,}|hvs\.[\w-]{20,}|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,})`)
	// a port, as in host:8443 (so "admin:pa" in front of a later @ is not taken for host:port)
	digits = regexp.MustCompile(`^[0-9]*$`)
)

// program says which short options of a known program carry a secret. Short options mean different things in
// different programs (-p is a password for mysql and a port for ssh), so they are only read for these.
type program struct {
	attached []string // the value is written onto the option: -pSECRET
	next     []string // the next argument is the value: -p SECRET (and -pSECRET)
	userPass []string // the value is user<sep>password: only the password is hidden
	sep      string   // separator in userPass values (default ":")
	wraps    bool     // runs another command (sshpass -p X ssh -p 22 host): its options end at the first other word
}

var (
	mysql   = &program{attached: []string{"-p"}}
	sevenZ  = &program{attached: []string{"-p"}}
	nextP   = &program{next: []string{"-p"}}
	sshpass = &program{next: []string{"-p"}, wraps: true}
	nextBig = &program{next: []string{"-P"}}
	ldap    = &program{next: []string{"-w"}}
	putty   = &program{next: []string{"-pw"}}
	smb     = &program{userPass: []string{"-U", "--user"}, sep: "%"}
	// docker login / podman login: only after the word "login" (docker run -p is a port)
	registryLogin = &program{next: []string{"-p"}}
	registryTools = map[string]bool{"docker": true, "podman": true, "nerdctl": true, "buildah": true, "skopeo": true, "helm": true, "oras": true}
)

var programs = map[string]*program{
	"mysql": mysql, "mysqldump": mysql, "mysqladmin": mysql, "mysqlcheck": mysql, "mysqlimport": mysql, "mysqlshow": mysql,
	"mysqlslap": mysql, "mysqlbinlog": mysql, "mysqlpump": mysql, "mycli": mysql,
	"mariadb": mysql, "mariadb-dump": mysql, "mariadb-admin": mysql, "mariadb-check": mysql, "mariadb-import": mysql,
	"mariadb-show": mysql, "mariadb-binlog": mysql, "mariadb-backup": mysql, "mariabackup": mysql,
	"7z": sevenZ, "7za": sevenZ, "7zr": sevenZ, "7zz": sevenZ,
	"sshpass": sshpass, "rdesktop": nextP, "useradd": nextP, "usermod": nextP,
	"mongo": nextP, "mongosh": nextP, "mongodump": nextP, "mongorestore": nextP, "mongoexport": nextP,
	"mongoimport": nextP, "mongostat": nextP, "mongotop": nextP,
	"unzip": nextBig, "zip": nextBig, "mosquitto_pub": nextBig, "mosquitto_sub": nextBig, "mosquitto_rr": nextBig,
	"sqlcmd": nextBig, "bcp": nextBig,
	"redis-cli":  {next: []string{"-a"}},
	"ldapsearch": ldap, "ldapadd": ldap, "ldapmodify": ldap, "ldapdelete": ldap, "ldappasswd": ldap, "ldapwhoami": ldap,
	"ldapcompare": ldap, "ldapmodrdn": ldap,
	"plink": putty, "pscp": putty, "psftp": putty, "putty": putty,
	"curl": {next: []string{"-b"}, userPass: []string{"-u", "--user", "-U", "--proxy-user", "-E", "--cert"}},
	"http": {userPass: []string{"-a"}}, "https": {userPass: []string{"-a"}},
	"lftp":      {userPass: []string{"-u", "--user"}, sep: ","},
	"smbclient": smb, "smbget": smb, "rpcclient": smb, "smbcacls": smb,
}

// what the next argument is, as far as the one before it told
const (
	nextNone     = iota
	nextSecret   // a secret, unless it starts with "-" (then it is the next option and the secret was left out)
	nextForced   // a secret, whatever it looks like
	nextUserPass // user:password
	nextCred     // after "Authorization:": a scheme word (Bearer, Basic) and then the secret, or the secret itself
	nextHeader   // after -H / --header: a header line
)

// scanner walks over the arguments of one command line.
type scanner struct {
	prog     *program
	progName string
	next     int
	sep      string // for nextUserPass
}

// Args redacts a command line given as its arguments and joins them with blanks, cut to maxLen characters (with
// an ellipsis). Use it where the arguments are known (the agent reads them from /proc): the filter then knows
// where a value ends, also when it contains blanks.
//
// Hidden, as "***":
//   - the user part of an address: scheme://user:SECRET@host and scheme://SECRET@host, up to the last "@" before
//     the first "/" (applied first, so a password with "=", ":" or "@" in it cannot confuse the other rules);
//   - the value of an option whose name contains a secret word (password, pass, pwd, token, secret, key, auth,
//     credential, bearer, cookie): --password=x, --password x, -token x, --api-key x;
//   - NAME=value where NAME contains such a word: API_KEY=x, password=x, also inside a query string
//     (?token=x&page=2 keeps page=2) and in JSON ("password":"x");
//   - header lines: "Authorization: Bearer x" (the token up to the next blank), "X-Api-Key: x", "Cookie: x",
//     and the word after a lone Bearer / Basic;
//   - short options of programs whose options are known: mysql -pX (and its relatives), sshpass -p X,
//     curl -u user:X, redis-cli -a X, 7z -pX, docker login -p X, and a few more (see programs);
//   - tokens with a recognisable shape wherever they stand (GitHub, GitLab, Slack, sk-..., Vault, JWT).
func Args(args []string, maxLen int) string {
	maxLen = limit(maxLen)
	s := &scanner{}
	var b strings.Builder
	n := 0
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
			n++
		}
		r := s.arg(head(a))
		b.WriteString(r)
		if n += utf8.RuneCountInString(r); n > maxLen { // the rest would be cut off anyway
			break
		}
	}
	return clip(b.String(), maxLen)
}

// Cmdline redacts a command line that is already one string and cuts it to maxLen characters (with an
// ellipsis). The same rules as Args, applied to the words between blanks: where a secret contains a blank, only
// its first word can be recognised. Redacting an already redacted line again changes nothing.
func Cmdline(cmd string, maxLen int) string {
	maxLen = limit(maxLen)
	return clip((&scanner{}).line(head(cmd), maxLen), maxLen)
}

func limit(maxLen int) int {
	if maxLen <= 0 {
		return 200
	}
	return maxLen
}

func clip(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	return string([]rune(s)[:maxLen-1]) + "…"
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// line redacts the words of a text, keeping the blanks between them. It stops soon after maxLen characters.
func (s *scanner) line(text string, maxLen int) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(text) && n <= maxLen; {
		j := i
		for j < len(text) && isBlank(text[j]) {
			j++
		}
		k := j
		for k < len(text) && !isBlank(text[k]) {
			k++
		}
		b.WriteString(text[i:j])
		n += j - i
		if k > j {
			r := s.word(text[j:k])
			b.WriteString(r)
			n += utf8.RuneCountInString(r)
		}
		i = k
	}
	return b.String()
}

// arg redacts one argument.
func (s *scanner) arg(a string) string {
	if !strings.ContainsAny(a, " \t\n\r") {
		return s.word(a)
	}
	// An argument with blanks in it: a value in one piece, a header line, or a whole command line of its own
	// (sh -c "...", a process that rewrote its title).
	next := s.next
	s.next = nextNone
	switch {
	case next == nextForced, next == nextCred, next == nextSecret && !strings.HasPrefix(a, "-"):
		return mask
	case next == nextUserPass && !strings.HasPrefix(a, "-"):
		return userPass(a, s.sep)
	case next == nextHeader:
		if r, more, ok := headerLine(a); ok {
			s.next = more
			return r
		}
	}
	if m := flagEq.FindStringSubmatch(a); m != nil {
		return m[1] + "=" + mask
	}
	if m := envEq.FindStringSubmatch(a); m != nil {
		return m[1] + "=" + mask
	}
	return (&scanner{}).line(a, len(a))
}

// quotes splits a word into leading quote characters, the word itself and trailing ones (a command line kept
// as one string still has the shell's quotes in it).
func quotes(w string) (pre, core, suf string) {
	i, j := 0, len(w)
	for i < j && (w[i] == '"' || w[i] == '\'') {
		i++
	}
	for j > i && (w[j-1] == '"' || w[j-1] == '\'') {
		j--
	}
	return w[:i], w[i:j], w[j:]
}

func hasSecretHint(lower string) bool {
	for _, h := range secretHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

func isScheme(lower string) bool {
	switch lower {
	case "bearer", "basic", "digest", "token", "negotiate", "apikey", "aws4-hmac-sha256":
		return true
	}
	return false
}

// word redacts one word (an argument without blanks, or one word of a longer text).
func (s *scanner) word(w string) string {
	pre, core, suf := quotes(w)
	if core == "" {
		return w
	}
	next := s.next
	s.next = nextNone
	switch next {
	case nextForced:
		return pre + mask + suf
	case nextSecret:
		if !strings.HasPrefix(core, "-") {
			return pre + mask + suf
		}
	case nextUserPass:
		if !strings.HasPrefix(core, "-") {
			return pre + userPass(core, s.sep) + suf
		}
	case nextCred:
		if isScheme(strings.ToLower(core)) {
			s.next = nextForced
			return w
		}
		return pre + mask + suf
	case nextHeader:
		if r, more, ok := headerLine(core); ok {
			s.next = more // "Authorization:" or "Authorization:Bearer" with the secret in the next words
			return pre + r + suf
		}
	}
	lower := strings.ToLower(core)
	hint := hasSecretHint(lower)
	if strings.Contains(core, "://") { // first: what is left of the "@" must not be read by the other rules
		core = urlAuthority.ReplaceAllStringFunc(core, userPart)
		if i := strings.Index(core, "://"); i >= 0 {
			core = core[:i+3] + lateUserPart(core[i+3:])
		}
	}
	switch {
	case hint && strings.HasSuffix(core, ":") && secretName.MatchString(core): // Authorization:  X-Api-Key:  {"password":
		s.next = nextCred
		return pre + core + suf
	case lower == "bearer" || lower == "basic" || strings.HasSuffix(lower, ":bearer") || strings.HasSuffix(lower, ":basic"):
		s.next = nextSecret
		return pre + core + suf
	case strings.HasPrefix(core, "-"):
		if hint {
			if m := flagEq.FindStringSubmatch(core); m != nil {
				return pre + m[1] + "=" + mask + suf
			}
			if flagOnly.MatchString(core) {
				s.next = nextSecret
				return pre + core + suf
			}
		}
		if core == "-H" || core == "--header" {
			s.next = nextHeader
			return pre + core + suf
		}
		if v, ok := strings.CutPrefix(core, "--header="); ok {
			if r, more, ok := headerLine(v); ok {
				s.next = more
				return pre + "--header=" + r + suf
			}
		}
		if r, ok := s.option(core); ok {
			return pre + r + suf
		}
	case strings.HasPrefix(core, "/") && strings.Contains(core, ":"):
		if m := slashOpt.FindStringSubmatch(core); m != nil {
			return pre + m[1] + ":" + mask + suf
		}
	default:
		s.program(lower)
	}
	if hint && strings.Contains(core, "=") {
		core = keyValues(core)
	}
	if strings.ContainsAny(core, "_-.") {
		core = shapes.ReplaceAllString(core, mask)
	}
	w = pre + core + suf
	if hint && strings.Contains(w, ":") { // on the whole word: the quotes around it can be the value's own
		w = jsonKV.ReplaceAllString(w, "${1}${2}"+mask+"${3}")
	}
	return w
}

// program remembers the program a word names, so that its short options can be read.
func (s *scanner) program(lower string) {
	base := lower
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".exe")
	if s.prog != nil && s.prog.wraps {
		s.prog = nil
	}
	if p, ok := programs[base]; ok {
		s.prog, s.progName = p, base
		return
	}
	switch {
	case registryTools[base]:
		s.prog, s.progName = nil, base
	case base == "login" && registryTools[s.progName]:
		s.prog = registryLogin
	}
}

// endsCluster reports whether core is a group of one-letter options that ends with the option o
// (curl -sSu user:password: the value of -u follows).
func endsCluster(core, o string) bool {
	if len(o) != 2 || len(core) < 3 || core[0] != '-' || core[len(core)-1] != o[1] {
		return false
	}
	for i := 1; i < len(core); i++ {
		if c := core[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// option handles the short (and user:password) options of the program seen last.
func (s *scanner) option(core string) (string, bool) {
	p := s.prog
	if p == nil {
		return "", false
	}
	for _, o := range p.userPass {
		sep := p.sep
		if sep == "" {
			sep = ":"
		}
		switch {
		case core == o, endsCluster(core, o):
			s.next, s.sep = nextUserPass, sep
			return core, true
		case strings.HasPrefix(o, "--") && strings.HasPrefix(core, o+"="):
			return o + "=" + userPass(core[len(o)+1:], sep), true
		case !strings.HasPrefix(o, "--") && strings.HasPrefix(core, o):
			return o + userPass(core[len(o):], sep), true
		}
	}
	for _, o := range p.next {
		if core == o || endsCluster(core, o) {
			s.next = nextSecret
			return core, true
		}
		if strings.HasPrefix(core, o) {
			return o + mask, true
		}
	}
	for _, o := range p.attached {
		if strings.HasPrefix(core, o) && len(core) > len(o) {
			return o + mask, true
		}
	}
	return "", false
}

// userPass hides what follows the first separator in user:password ("user" alone stays).
func userPass(v, sep string) string {
	user, _, ok := strings.Cut(v, sep)
	if !ok {
		return v
	}
	return user + sep + mask
}

// userPart hides the user part of one scheme://authority: everything up to the last "@", keeping the user
// name when there is a "user:" in front of the secret.
func userPart(m string) string {
	i := strings.Index(m, "://") + 3
	auth := m[i:]
	at := strings.LastIndex(auth, "@")
	if at < 0 {
		return m
	}
	return m[:i] + maskUser(auth[:at]) + auth[at:]
}

func maskUser(userinfo string) string {
	if user, _, ok := strings.Cut(userinfo, ":"); ok {
		return user + ":" + mask
	}
	return mask
}

// lateUserPart handles a password with a "/" in it (scheme://user:pa/ss@host), which ends the authority early:
// when what stands before the first "/" is "user:something" and that something is not a port, the user part
// goes up to the last "@" of the word.
func lateUserPart(rest string) string {
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return rest
	}
	auth := rest[:slash]
	colon := strings.LastIndexByte(auth, ':')
	at := strings.LastIndexByte(rest, '@')
	if colon < 0 || at < slash || strings.Contains(auth, "@") || strings.HasPrefix(auth, "[") || digits.MatchString(auth[colon+1:]) {
		return rest
	}
	return maskUser(rest[:at]) + rest[at:]
}

// headerLine redacts "Name: value" when the name says it holds a secret ("Authorization: Bearer x" keeps the
// word Bearer). ok is false for other headers and for text that is no header. next says what the following
// word is when the line stops early: nextCred after "Authorization:", nextForced after "Authorization:Bearer".
func headerLine(h string) (line string, next int, ok bool) {
	name, value, found := strings.Cut(h, ":")
	if !found || name == "" || strings.ContainsAny(name, " \t") || !hasSecretHint(strings.ToLower(name)) || !secretName.MatchString(name) {
		return "", nextNone, false
	}
	f := strings.Fields(value)
	switch {
	case len(f) == 0:
		return name + ":", nextCred, true
	case len(f) == 1 && isScheme(strings.ToLower(f[0])):
		return h, nextForced, true
	case len(f) >= 2 && isScheme(strings.ToLower(f[0])):
		return name + ": " + f[0] + " " + mask, nextNone, true
	case strings.HasPrefix(value, " "):
		return name + ": " + mask, nextNone, true
	}
	return name + ":" + mask, nextNone, true
}

// keyValues hides the value of every NAME=value inside a word whose NAME holds a secret word. The value runs to
// the end of the word, or to the next "&name=" of a query string.
func keyValues(w string) string {
	var b strings.Builder
	for {
		loc := kvName.FindStringIndex(w)
		if loc == nil || loc[1] == len(w) {
			break
		}
		end := len(w)
		for i := loc[1]; i < len(w); i++ {
			if w[i] == '&' && queryNext.MatchString(w[i:]) {
				end = i
				break
			}
		}
		b.WriteString(w[:loc[1]])
		b.WriteString(mask)
		w = w[end:]
	}
	if b.Len() == 0 {
		return w
	}
	b.WriteString(w)
	return b.String()
}
