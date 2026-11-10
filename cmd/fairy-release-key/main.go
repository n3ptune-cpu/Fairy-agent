// Command fairy-release-key makes and uses the release signing key of Fairy-agent and Fairy-dashboard.
//
//	go run ./cmd/fairy-release-key gen [--private FILE] [--public FILE]
//	    new key pair: the private key (for the secret FAIRY_RELEASE_KEY of the GitHub Environment "release"
//	    in both repositories, never a repository secret) and the public key (commit it as release/signing.pub
//	    in both repositories). Run it once, on your own PC.
//	go run ./cmd/fairy-release-key sign --pub release/signing.pub FILE
//	    writes FILE.sig; the private key comes from $FAIRY_RELEASE_KEY (or --key-file). Used by the release workflow.
//	go run ./cmd/fairy-release-key verify --pub release/signing.pub FILE
//	    checks FILE.sig (e.g. a downloaded SHA256SUMS).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

const usage = `fairy-release-key: the release signing key of Fairy-agent and Fairy-dashboard

  gen    [--private FILE] [--public FILE]   make a new key pair (once; see SETUP-UPDATES.md)
  sign   --pub FILE [--key-file FILE] FILE  write FILE.sig (private key from $FAIRY_RELEASE_KEY)
  verify --pub FILE FILE                    check FILE.sig
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = gen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy-release-key:", err)
		os.Exit(1)
	}
}

// genMessage tells the owner what to do with a new key pair. The private key belongs in the GitHub
// Environment "release" of each repository (the release workflows run with `environment: release`, so the job
// waits for the required reviewer before it can read the key). A repository secret can be read by every
// workflow run of the repository, without that approval.
func genMessage(priv, pub string) string {
	return fmt.Sprintf(`New release key made.

  private key: %s
      Store its one line as the secret FAIRY_RELEASE_KEY of the GitHub Environment "release", in BOTH
      repositories (Settings > Environments > release > Environment secrets > Add environment secret).
      Do NOT add it as a repository secret (Settings > Secrets and variables > Actions): every workflow
      run could read it there, without the approval the environment asks for. If the repository has
      such a secret from an earlier setup, delete it. SETUP-UPDATES.md has the environment's settings.
      Then keep this file somewhere safe and offline (or delete it: a lost key only means making a new
      one and one more manual update). Never commit it.
  public key:  %s
      Commit this file in Fairy-agent AND copy it to release/signing.pub in Fairy-dashboard and commit it there.
      Release builds carry it and accept only updates signed with the private key.
`, priv, pub)
}

func defaultPrivate() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, "fairy-release-key.txt")
	}
	return "fairy-release-key.txt"
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; not overwriting it (move it away first if you really want a new key)", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func gen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	priv := fs.String("private", defaultPrivate(), "where to write the private key (keep it secret, outside the repository)")
	pub := fs.String("public", filepath.Join("release", "signing.pub"), "where to write the public key (commit this file)")
	_ = fs.Parse(args)
	pubS, privS, err := release.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*pub), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(*pub); err == nil {
		return fmt.Errorf("%s already exists; not overwriting it", *pub)
	}
	if err := writeNew(*priv, []byte(privS+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeNew(*pub, []byte(pubS+"\n"), 0o644); err != nil {
		os.Remove(*priv)
		return err
	}
	fmt.Print(genMessage(*priv, *pub))
	return nil
}

func readPub(path string) (string, error) {
	if path == "" {
		return "", errors.New("--pub is required (release/signing.pub)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w (make the key first: fairy-release-key gen, and commit release/signing.pub)", err)
	}
	if _, err := release.ParsePublicKey(string(b)); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	pubPath := fs.String("pub", "", "the public key file (release/signing.pub): the private key must match it")
	keyFile := fs.String("key-file", "", "read the private key from this file instead of $FAIRY_RELEASE_KEY")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("sign needs exactly one file (SHA256SUMS)")
	}
	pub, err := readPub(*pubPath)
	if err != nil {
		return err
	}
	raw := os.Getenv("FAIRY_RELEASE_KEY")
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		raw = string(b)
	}
	if strings.TrimSpace(raw) == "" {
		return errors.New("no private key: the FAIRY_RELEASE_KEY secret is missing or empty " +
			"(GitHub: Settings > Secrets and variables > Actions; see SETUP-UPDATES.md)")
	}
	k, err := release.ParsePrivateKey(raw)
	if err != nil {
		return err
	}
	if release.PublicOf(k) != pub {
		return fmt.Errorf("the private key does not belong to %s (FAIRY_RELEASE_KEY and release/signing.pub come from different `gen` runs)", *pubPath)
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := os.WriteFile(fs.Arg(0)+".sig", release.Sign(k, data), 0o644); err != nil {
		return err
	}
	fmt.Println("signed", fs.Arg(0), "->", fs.Arg(0)+".sig")
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "the public key file (release/signing.pub)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("verify needs exactly one file (SHA256SUMS)")
	}
	pubS, err := readPub(*pubPath)
	if err != nil {
		return err
	}
	pub, _ := release.ParsePublicKey(pubS)
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(fs.Arg(0) + ".sig")
	if err != nil {
		return err
	}
	if err := release.VerifySignature(pub, data, sig); err != nil {
		return err
	}
	fmt.Println("OK: signature of", fs.Arg(0), "is good")
	return nil
}
