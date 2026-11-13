package redact

// Audit 3, L19: the forms of passing a secret that the filter missed, or hid only in part, next to the ones
// it already knew. Every case is checked three ways: as one string (Cmdline, what the panel and old agents
// use), as arguments (Args, what the agent uses on Linux), and filtered a second time (must not change).

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// The made-up values below that have the form of a real credential (a token with a service's prefix, a JSON
// web token, an address with a password in it) are put together from pieces when the tests run: no text in
// the test files of this package has such a form. GitHub's push protection, which reads the source, once
// refused a push because of one of them. What each case tests is the same value as before.
func madeUp(pieces ...string) string { return strings.Join(pieces, "") }

// b64 is the base64url text of s, as the parts of a JSON web token are.
func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

var (
	alnum36 = "abcdefghijklmnopqrstuvwxyz" + "0123456789"

	tokGitHub = madeUp("gh", "p", "_", alnum36)                                                                           // GitHub's personal token: the prefix, 36 letters and digits
	tokVault  = madeUp("hv", "s", ".", "CAESIJ", alnum36[:32])                                                            // a Vault service token
	tokSlack  = madeUp("xo", "xb", "-", "1234567890", "-", alnum36[:14])                                                  // a Slack bot token
	tokLLM    = madeUp("s", "k", "-", "ant", "-", alnum36[:30])                                                           // an API key with the sk- prefix
	tokJWT    = madeUp(b64(`{"alg":"HS256"}`), ".", b64(`{"sub":"1234567890"}`), ".", b64("made-up signature of a test")) // header.payload.signature
	tokBearer = madeUp("e", "yJ", "abc", ".", "def")                                                                      // the beginning of a JSON web token
	tokAWS    = madeUp("AK", "IA", "XYZ")                                                                                 // the prefix of an AWS access key id
	tokShort  = madeUp("s", "k", "-", "1")                                                                                // an API key far too short to be recognised by its form
	tokBasic  = b64("user:pass")                                                                                          // what `Authorization: Basic` carries

	// addresses with a password: scheme, user, password, host
	addr = func(scheme, user, password, rest string) string {
		return madeUp(scheme, "://", user, ":", password, "@", rest)
	}
)

// leaks: a command line and the pieces of the secret that must not survive.
var leaks = []struct {
	cmd     string
	secrets []string
}{
	// short options of known programs
	{"mysql -u root -pS3cretPw appdb", []string{"S3cretPw"}},
	{"mysqldump -uroot -pS3cretPw --all-databases", []string{"S3cretPw"}},
	{"mariadb-dump -pS3cretPw appdb", []string{"S3cretPw"}},
	{"sudo -u backup /usr/bin/mysql -pS3cretPw appdb", []string{"S3cretPw"}},
	{"sshpass -p S3cretPw ssh root@host", []string{"S3cretPw"}},
	{"sshpass -pS3cretPw ssh root@host", []string{"S3cretPw"}},
	{"curl -u admin:S3cretPw https://example.com/", []string{"S3cretPw"}},
	{"curl -uadmin:S3cretPw https://example.com/", []string{"S3cretPw"}},
	{"curl -fsSu admin:S3cretPw https://example.com/", []string{"S3cretPw"}},
	{"/usr/bin/curl --user admin:S3cretPw https://example.com/", []string{"S3cretPw"}},
	{"curl --user=admin:S3cretPw https://example.com/", []string{"S3cretPw"}},
	{"curl --proxy-user admin:S3cretPw -x proxy:3128 https://example.com/", []string{"S3cretPw"}},
	{"curl -b session=S3cretSess https://example.com/", []string{"S3cretSess"}},
	{"curl --oauth2-bearer S3cretTok https://example.com/", []string{"S3cretTok"}},
	{"redis-cli -h cache -a S3cretPw ping", []string{"S3cretPw"}},
	{"ldapsearch -x -D cn=admin,dc=example -w S3cretPw -b dc=example", []string{"S3cretPw"}},
	{"mongosh --host db -u root -p S3cretPw", []string{"S3cretPw"}},
	{"7z a -pS3cretPw backup.7z /srv/data", []string{"S3cretPw"}},
	{"docker login -u me -p S3cretPw ghcr.io", []string{"S3cretPw"}},
	{"unzip -P S3cretPw archive.zip", []string{"S3cretPw"}},
	{"mosquitto_pub -h broker -u dev -P S3cretPw -t home/x -m on", []string{"S3cretPw"}},
	{"smbclient //nas/share -U bob%S3cretPw", []string{"S3cretPw"}},
	{"lftp -u bob,S3cretPw ftp.example.com", []string{"S3cretPw"}},
	{"plink -ssh host -l root -pw S3cretPw", []string{"S3cretPw"}},
	{"useradd -m -p $6$salt$S3cretHash bob", []string{"S3cretHash", "$6$salt"}},
	{"xfreerdp /u:bob /p:S3cretPw /v:host", []string{"S3cretPw"}},
	// addresses
	{"curl " + addr("https", "bob", "s3cr3t", "example.com/x"), []string{"s3cr3t"}},
	{"curl " + addr("https", "admin", "pAss0=", "host/path"), []string{"pAss0"}},
	{"curl " + addr("https", "admin", "p@ss:w0rd", "host/"), []string{"p@ss", "w0rd"}},
	{"psql " + addr("postgresql", "app", "S3cret/Pw", "db.internal:5432/app"), []string{"S3cret", "Pw@"}},
	{"git clone https://" + tokGitHub + "@github.com/o/r.git", []string{tokGitHub[:14]}},
	{"git clone https://S3cretTok@git.example.com/o/r.git", []string{"S3cretTok"}},
	{"wget " + addr("ftp", "bob", "S3cretPw", "ftp.example.com/file"), []string{"S3cretPw"}},
	{"mongodump --uri=" + addr("mongodb", "root", "S3cretPw", "db:27017/app"), []string{"S3cretPw"}},
	// headers
	{"curl -H 'Authorization: Bearer " + tokBearer + "' https://x", []string{tokBearer[:6]}},
	{"curl -H 'Authorization: Bearer tok!en:with|odd%chars' https://x", []string{"tok!en", "with|odd", "odd%chars"}},
	{"curl -H Authorization:Bearer S3cretTok https://x", []string{"S3cretTok"}},
	{"curl -H 'Authorization: token S3cretTok' https://x", []string{"S3cretTok"}},
	{"curl -H 'Authorization: S3cretTok' https://x", []string{"S3cretTok"}},
	{"curl -H 'X-Api-Key: S3cretKey' https://x", []string{"S3cretKey"}},
	{"curl -H X-Api-Key:S3cretKey https://x", []string{"S3cretKey"}},
	{"curl --header=PRIVATE-TOKEN:S3cretTok https://gitlab.example.com/api/v4/projects", []string{"S3cretTok"}},
	{"curl -H 'Cookie: session=S3cretSess' https://x", []string{"S3cretSess"}},
	{"git -c http.extraHeader=Authorization: Basic " + tokBasic + " ls-remote origin", []string{tokBasic}},
	// options and variables with a secret word
	{"mysql -u root --password=hunter2 -h db", []string{"hunter2"}},
	{"app --token abc123 --verbose", []string{"abc123"}},
	{"API_KEY=xyz123 ./run.sh", []string{"xyz123"}},
	{"env MYSQL_PWD=S3cretPw mysql appdb", []string{"S3cretPw"}},
	{"rclone sync --s3-secret-access-key " + tokAWS + " remote:", []string{tokAWS}},
	{"wget --http-password=S3cretPw http://example.com/file", []string{"S3cretPw"}},
	{"openssl enc -aes-256-cbc -pass pass:S3cretPw -in a -out b", []string{"S3cretPw"}},
	{"java -Dspring.datasource.password=S3cretPw -jar app.jar", []string{"S3cretPw"}},
	{"mount -t cifs //nas/s /mnt -o username=bob,password=S3cretPw", []string{"S3cretPw"}},
	{"curl https://api.example.com/v1?token=S3cretTok&page=2", []string{"S3cretTok"}},
	{"curl -d password=S3c&retPw https://x", []string{"S3c", "retPw"}},
	{`curl -d {"user":"bob","password":"S3cretPw"} https://x`, []string{"S3cretPw"}},
	{`curl -d '{"user":"bob","password":"S3cretPw"}' https://x`, []string{"S3cretPw"}},
	{`curl -d "password":"S3cretPw" https://x`, []string{"S3cretPw"}},
	{`curl -d {"password": "S3cretPw"} https://x`, []string{"S3cretPw"}},
	{"app --token --password secret", []string{"secret"}},
	// recognisable tokens anywhere
	{"vault login " + tokVault, []string{"CAESIJ"}},
	{"deploy.sh " + tokGitHub + " prod", []string{tokGitHub[:7]}},
	{"notify " + tokSlack + " #alerts", []string{tokSlack[:9]}},
	{"llm-proxy " + tokLLM, []string{tokLLM[:10]}},
	{"jwt-tool " + tokJWT, []string{tokJWT[:8], tokJWT[strings.LastIndex(tokJWT, ".")+1:][:6]}},
}

// The made-up values have the forms they are meant to have (they are no longer written out above, where a
// slip in a piece would turn a case into one that tests nothing).
func TestMadeUpValuesHaveTheirForms(t *testing.T) {
	for value, want := range map[string]struct {
		prefix string
		length int
	}{
		tokGitHub: {"gh" + "p_abcdefghij", 40},
		tokVault:  {"hv" + "s.CAESIJabc", 42},
		tokSlack:  {"xo" + "xb-1234567890-abc", 30},
		tokLLM:    {"s" + "k-ant-abcdefg", 37},
		tokJWT:    {"e" + "yJhbGciOiJIUzI1NiJ9.e" + "yJzdWIiOiIxMjM0NTY3ODkwIn0.", 85},
		tokBearer: {"e" + "yJabc.def", 10},
		tokAWS:    {"AK" + "IAXYZ", 7},
		tokShort:  {"s" + "k-1", 4},
		tokBasic:  {"dXNlcjp" + "wYXNz", 12},
		addr("https", "bob", "s3cr3t", "example.com/x"): {"https://bob" + ":s3cr3t" + "@example.com/x", 32},
	} {
		if !strings.HasPrefix(value, want.prefix) || len(value) != want.length {
			t.Errorf("a made-up value of %d characters, want %d beginning with %q", len(value), want.length, want.prefix)
		}
	}
	for _, tok := range []string{tokGitHub, tokVault, tokSlack, tokLLM, tokJWT} { // the ones that are found by their form alone
		if !shapes.MatchString(tok) {
			t.Errorf("the made-up value beginning with %q no longer has a form the filter knows", tok[:6])
		}
	}
	for _, tok := range []string{tokBearer, tokAWS, tokShort, tokBasic} { // the ones that are hidden for where they stand
		if shapes.MatchString(tok) {
			t.Errorf("the made-up value %q has a form the filter knows: its case would no longer test the option or the header", tok)
		}
	}
}

// unchanged: ordinary command lines the filter must leave exactly as they are (it must stay useful).
var unchanged = []string{
	"llama-server -m /models/q.gguf -ngl 99 --split-mode layer --port 8080 --host 100.64.0.12",
	"ssh -p 2222 root@host",
	"docker run -d -p 8080:80 -u 1000:1000 --name web nginx:1.27",
	"mkdir -p /srv/data",
	"find / -path /proc -prune -o -print",
	"gcc -pthread -pipe -O2 -o app main.c",
	"ffmpeg -i in.mp4 -preset fast -pix_fmt yuv420p out.mp4",
	"psql -h db -p 5432 -U app appdb",
	"redis-cli -h cache -p 6379 ping",
	"mysql -u root -P 3306 -h db appdb",
	"mysql -u root -p appdb",
	"curl -u admin https://example.com/",
	"curl -fsSL -o /tmp/install.sh https://example.com/install.sh",
	"curl -sSu admin https://example.com/",
	"curl -sS -o /dev/null https://example.com:8443/path/user@example.com",
	"curl -H 'Content-Type: application/json' -H Accept:*/* https://x",
	"/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --port=41641",
	`C:\Program Files\obs-studio\bin\64bit\obs64.exe`,
	`C:\Program Files\KeePass Password Safe 2\KeePass.exe`,
	"nginx: master process /usr/sbin/nginx -g daemon off;",
	"python3 /opt/app/server.py --host 0.0.0.0 --port 8000 --workers 4",
	"rsync -avz -e ssh /src/ backup@host:/dst/",
	"sshd: root@pts/0",
	"tar -cpf out.tar dir",
	"git clone https://github.com/n3ptune-cpu/Fairy-agent.git",
	"unzip -p archive.zip file.txt",
	"mosquitto_sub -h broker -p 1883 -t home/#",
	"/usr/local/bin/fairy-agent run",
	"app --token -v",
	"sshpass -e ssh root@host",
	"docker run -p 5432:5432 postgres:17",
	"/sbin/init",
	"",
}

func hidden(t *testing.T, how, in, out string, secrets []string) {
	t.Helper()
	if !strings.Contains(out, "***") {
		t.Errorf("%s: nothing hidden: %q -> %q", how, in, out)
	}
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("%s: %q still shows %q: %q", how, in, s, out)
		}
	}
}

func TestSecretForms(t *testing.T) {
	if len(leaks) < 23 {
		t.Fatal("the audit's list had 23 forms")
	}
	for _, c := range leaks {
		one := Cmdline(c.cmd, 300)
		hidden(t, "Cmdline", c.cmd, one, c.secrets)
		if again := Cmdline(one, 300); again != one {
			t.Errorf("Cmdline twice: %q -> %q -> %q", c.cmd, one, again)
		}
		args := Args(strings.Fields(c.cmd), 300)
		hidden(t, "Args", c.cmd, args, c.secrets)
		if again := Cmdline(args, 300); again != args { // the agent's server and the panel filter the string again
			t.Errorf("Args then Cmdline: %q -> %q -> %q", c.cmd, args, again)
		}
	}
}

func TestOrdinaryCommandLinesStay(t *testing.T) {
	for _, c := range unchanged {
		if got := Cmdline(c, 300); got != c {
			t.Errorf("Cmdline changed %q -> %q", c, got)
		}
		if got := Args(strings.Fields(c), 300); got != strings.Join(strings.Fields(c), " ") {
			t.Errorf("Args changed %q -> %q", c, got)
		}
	}
}

// What is shown next to the hidden part: the filter must not hide more than it has to in the common cases.
func TestExactResults(t *testing.T) {
	for in, want := range map[string]string{
		"mysql -u root -pS3cretPw appdb":                                                 "mysql -u root -p*** appdb",
		"sshpass -p S3cretPw ssh -p 2222 root@host":                                      "sshpass -p *** ssh -p 2222 root@host",
		"curl -u admin:S3cretPw https://example.com/":                                    "curl -u admin:*** https://example.com/",
		"curl " + addr("https", "admin", "pAss0=", "host/path"):                          "curl " + addr("https", "admin", "***", "host/path"),
		"curl " + addr("https", "admin", "p@ss:w0rd", "host/"):                           "curl " + addr("https", "admin", "***", "host/"),
		"psql " + addr("postgresql", "app", "S3cret/Pw", "db.internal:5432/app"):         "psql " + addr("postgresql", "app", "***", "db.internal:5432/app"),
		"git clone https://S3cretTok@git.example.com/o/r.git":                            "git clone https://***@git.example.com/o/r.git",
		"curl -H 'Authorization: Bearer tok!en:with|odd%chars' https://x":                "curl -H 'Authorization: Bearer ***' https://x",
		"curl -H X-Api-Key:S3cretKey https://x":                                          "curl -H X-Api-Key:*** https://x",
		"curl https://api.example.com/v1?token=S3cretTok&page=2":                         "curl https://api.example.com/v1?token=***&page=2",
		`curl -d {"user":"bob","password":"S3cretPw"} https://x`:                         `curl -d {"user":"bob","password":"***"} https://x`,
		"docker login -u me -p S3cretPw ghcr.io":                                         "docker login -u me -p *** ghcr.io",
		"llama-server -m /models/q.gguf --port 8080 --api-key " + tokShort:               "llama-server -m /models/q.gguf --port 8080 --api-key ***",
		"backup.exe --password=hunter2 --target s3":                                      "backup.exe --password=*** --target s3",
		"python3 /opt/bench/stream_chat.py --endpoint http://127.0.0.1:8080 --token=abc": "python3 /opt/bench/stream_chat.py --endpoint http://127.0.0.1:8080 --token=***",
	} {
		if got := Cmdline(in, 300); got != want {
			t.Errorf("Cmdline(%q)\n got %q\nwant %q", in, got, want)
		}
		if got := Args(strings.Fields(in), 300); got != want {
			t.Errorf("Args(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// With the arguments known, a value is hidden whole even when it contains blanks, and a command line inside
// one argument (sh -c "...") is filtered like any other.
func TestArgsKnowWhereAValueEnds(t *testing.T) {
	for _, c := range []struct {
		args    []string
		want    string
		secrets []string
	}{
		{[]string{"app", "--password", "my secret phrase", "--verbose"}, "app --password *** --verbose", []string{"secret", "phrase"}},
		{[]string{"app", "--password=my secret phrase"}, "app --password=***", []string{"phrase"}},
		{[]string{"env", "DB_PASSWORD=my secret phrase", "app"}, "env DB_PASSWORD=*** app", []string{"phrase"}},
		{[]string{"curl", "-H", "Authorization: Bearer abc def", "https://x"}, "curl -H Authorization: Bearer *** https://x", []string{"abc", "def"}},
		{[]string{"curl", "-H", "Cookie: session=S3cretSess; theme=dark", "https://x"}, "curl -H Cookie: *** https://x", []string{"S3cretSess", "theme"}},
		{[]string{"curl", "-H", "Content-Type: application/json", "https://x"}, "curl -H Content-Type: application/json https://x", nil},
		{[]string{"curl", "-u", "admin:my secret phrase", "https://x"}, "curl -u admin:*** https://x", []string{"phrase"}},
		{[]string{"sh", "-c", "mysql -uroot -pS3cretPw appdb < dump.sql"}, "sh -c mysql -uroot -p*** appdb < dump.sql", []string{"S3cretPw"}},
		{[]string{"bash", "-c", "export API_TOKEN=S3cretTok && ./deploy.sh"}, "bash -c export API_TOKEN=*** && ./deploy.sh", []string{"S3cretTok"}},
		{[]string{"postgres: app appdb 10.0.0.5(51234) idle"}, "postgres: app appdb 10.0.0.5(51234) idle", nil},
		{[]string{"sshpass", "-p", "pw with blank", "ssh", "host"}, "sshpass -p *** ssh host", []string{"blank"}},
		{nil, "", nil},
		{[]string{""}, "", nil},
	} {
		got := Args(c.args, 300)
		if got != c.want {
			t.Errorf("Args(%q)\n got %q\nwant %q", c.args, got, c.want)
		}
		for _, s := range c.secrets {
			if strings.Contains(got, s) {
				t.Errorf("Args(%q) still shows %q: %q", c.args, s, got)
			}
		}
	}
}

func TestLengthLimit(t *testing.T) {
	if n := len([]rune(Cmdline(strings.Repeat("x", 500), 200))); n != 200 {
		t.Fatal(n)
	}
	if n := len([]rune(Args([]string{strings.Repeat("ä", 500)}, 200))); n != 200 {
		t.Fatal(n)
	}
	if got := Cmdline(strings.Repeat("ab ", 400), 0); len([]rune(got)) != 200 || !strings.HasSuffix(got, "…") { // 0 = 200
		t.Fatal(got)
	}
	// a secret that begins before the cut is hidden, not cut in half
	long := strings.Repeat("a", 280) + " --password=" + strings.Repeat("S", 100)
	if got := Cmdline(long, 300); strings.Contains(got, "SS") || !strings.HasSuffix(got, "--password=***") {
		t.Fatal(got)
	}
	args := make([]string, 0, 2100)
	for i := 0; i < 2000; i++ {
		args = append(args, "x")
	}
	args = append(args, "--password=S3cretPw")
	if got := Args(args, 300); len([]rune(got)) != 300 || strings.Contains(got, "S3cretPw") {
		t.Fatal(got)
	}
}

// A line of megabytes (a hostile agent can send one to the panel) costs no more than a line of maxInput bytes,
// and nothing beyond that point is shown.
func TestHugeInputIsCut(t *testing.T) {
	start := time.Now()
	for _, unit := range []string{"a", "password", "key=&a=", "x&token=1", "://@:", "https://a:b@c/", `"password":"`} {
		in := strings.Repeat(unit, (4<<20)/len(unit))
		for _, got := range []string{Cmdline(in, 300), Args([]string{in}, 300), Args([]string{"mysql", in, in}, 300)} {
			if n := len([]rune(got)); n > 300 {
				t.Fatalf("%q: %d characters", unit, n)
			}
		}
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("too slow: %v", d)
	}
	// a secret-bearing option right at the cut is still hidden; what follows the cut is gone
	in := "tool --password=" + strings.Repeat("S", maxInput) + " --token=T0ken"
	if got := Cmdline(in, 300); got != "tool --password=***" {
		t.Fatalf("%.80q", got)
	}
	if got := Args([]string{"tool", "--name=" + strings.Repeat("n", 2*maxInput), "next"}, 30); len([]rune(got)) != 30 || !strings.HasPrefix(got, "tool --name=nnn") {
		t.Fatalf("%q", got)
	}
}

// The filter runs over every process of the machine for each process list: it must stay cheap on command
// lines made to be expensive (many short words, long words full of hint letters).
func TestHostileCommandLinesAreCheap(t *testing.T) {
	inputs := []string{
		strings.Repeat("a ", 2048),
		strings.Repeat("key=", 1024),
		strings.Repeat("-p ", 1365),
		strings.Repeat("https://a:b@c/ ", 256),
		strings.Repeat("password", 512),
		strings.Repeat("://@:", 800),
		"mysql " + strings.Repeat("-p", 2000),
		strings.Repeat(`"password":"`, 340),
	}
	start := time.Now()
	for i := 0; i < 50; i++ {
		for _, in := range inputs {
			_ = Cmdline(in, 300)
			_ = Args(strings.Fields(in), 300)
			_ = Args([]string{in}, 300)
		}
	}
	// 1200 calls on 4 KiB inputs; a process list of a busy machine is a few hundred calls.
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("too slow: %v", d)
	}
}
