package release_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// L29 (the part the review found open, N2): install.ps1 checks what it downloaded and then runs it as
// Administrator from its work folder. That folder was made in the user's own %TEMP% and restricted
// afterwards; a program of the same administrator that is not elevated may rename what is in that %TEMP%
// whatever its permissions, and so could swap the whole folder after the check.
//
// Nothing here runs the script (there is no PowerShell where these tests run): the test pins, in the script's
// text, the properties the fix rests on, so that a later edit cannot quietly take one away.
func TestInstallPS1WorkFolderCannotBeSwapped(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	// the code without comment lines and the help block
	var code []string
	inHelp := false
	for _, l := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		switch s := strings.TrimSpace(l); {
		case strings.HasPrefix(s, "<#"):
			inHelp = true
		case strings.HasPrefix(s, "#>"):
			inHelp = false
		case inHelp, strings.HasPrefix(s, "#"), s == "":
		default:
			code = append(code, l)
		}
	}
	ps := strings.Join(code, "\n")
	line := func(re string) int {
		for i, l := range code {
			if regexp.MustCompile(re).MatchString(l) {
				return i
			}
		}
		t.Fatalf("install.ps1: no line matches %s", re)
		return -1
	}

	// 1. the work folder is in C:\Windows\Temp, with a random name; the user's %TEMP% is not used at all
	if regexp.MustCompile(`(?i)\$env:TE?MP\b`).MatchString(ps) || strings.Contains(ps, "GetTempPath") {
		t.Error("install.ps1 uses the user's temp folder, where a program of the same user that is not elevated may rename the work folder")
	}
	dir := line(`^\$dir = Join-Path \(Join-Path \$env:SystemRoot 'Temp'\) \('fairy-install-' \+ \[guid\]::NewGuid\(\)\.ToString\('N'\)\)$`)

	// 2. it is created together with its permissions (one call), not restricted afterwards
	sddl := line(`\$sec\.SetSecurityDescriptorSddlForm\('O:BAD:PAI\(A;OICI;FA;;;BA\)\(A;OICI;FA;;;SY\)'\)`)
	create := line(`\[System\.IO\.Directory\]::CreateDirectory\(\$dir, \$sec\)`)
	if !(dir < sddl && sddl <= create) {
		t.Error("install.ps1: the work folder is not created with its permissions")
	}
	for _, bad := range []string{"icacls", "Set-Acl", "SetAccessControl", "New-Item -ItemType Directory"} {
		if strings.Contains(ps, bad) {
			t.Errorf("install.ps1 uses %s: the work folder must get its permissions in the call that creates it", bad)
		}
	}
	// a folder of that name that exists already is refused (the create call would return it as it is)
	if exists := line(`^if \(Test-Path -LiteralPath \$dir\) \{ throw `); exists > create {
		t.Error("install.ps1: the check that the work folder is new comes after it is created")
	}

	// 3. what the create call made is looked at before the first download: owner, nothing inherited, entries
	//    for Administrators and SYSTEM only, empty
	look := line(`\$admins -notcontains \$acl\.GetOwner\(\$sid\)\.Value\) -or \(-not \$acl\.AreAccessRulesProtected\) -or \$rules\.Count -eq 0 -or \$bad\.Count -ne 0`)
	empty := line(`Get-ChildItem -LiteralPath \$dir -Force\)\.Count -ne 0`)
	download := line(`Invoke-WebRequest .* -OutFile \(Join-Path \$dir \$f\)`)
	if !(create < look && look < empty && empty < download) {
		t.Errorf("install.ps1: the order is not create (%d), look at the permissions (%d), empty (%d), download (%d)", create, look, empty, download)
	}
	line(`^\$admins = 'S-1-5-32-544', 'S-1-5-18'`)
	line(`\$bad = @\(\$rules \| Where-Object \{ \$admins -notcontains \$_\.IdentityReference\.Value \}\)`)

	// 4. every file that is run is hashed again in the moment before it runs
	check := line(`^\s*function Assert-Checked\(\[string\]\$f\) \{$`)
	if !strings.Contains(code[check+1], "Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dir $f)") || !strings.Contains(code[check+2], "$sums[$f]") || !strings.Contains(code[check+2], "throw") {
		t.Error("install.ps1: Assert-Checked does not compare the file's SHA-256 with SHA256SUMS")
	}
	run1 := line(`Invoke-Quiet \$new @\('verify-release', \$dir\)`)
	run2 := line(`^\s*& \$ps @instArgs$`)
	if !strings.Contains(code[run1-1], "Assert-Checked 'fairy-agent-windows-amd64.exe'") {
		t.Error("install.ps1: the downloaded program is not hashed again right before it is run")
	}
	if !strings.Contains(code[run2-2], "Assert-Checked 'install-fairy-agent.ps1'") || !strings.Contains(code[run2-1], "Assert-Checked 'fairy-agent-windows-amd64.exe'") {
		t.Error("install.ps1: install-fairy-agent.ps1 and the program it installs are not hashed again right before it is run")
	}
	// nothing else from the work folder is run
	for i, l := range code {
		if strings.Contains(l, "$dir") && regexp.MustCompile(`^\s*&\s`).MatchString(l) && i != run2 {
			t.Errorf("install.ps1 runs something else from the work folder: %s", strings.TrimSpace(l))
		}
	}

	// 5. Windows PowerShell 5.1 only knows these: no operator of PowerShell 7
	for name, re := range map[string]string{
		"&& or ||":            `(&&|\|\|)`,
		"?? or ?.":            `(\?\?|\?\.)`,
		"a ternary":           `\s\?\s[^\n]*\s:\s`,
		"-Parallel":           `(?i)-Parallel\b`,
		"a pipeline chain op": `(?i)\bForEach-Object\s+-Parallel`,
	} {
		if regexp.MustCompile(re).MatchString(ps) {
			t.Errorf("install.ps1 uses %s, which Windows PowerShell 5.1 does not have", name)
		}
	}
	// the one call that Windows PowerShell does not have is only reached in PowerShell 7
	core := line(`\[System\.IO\.FileSystemAclExtensions\]::Create\(`)
	if !strings.HasPrefix(strings.TrimSpace(code[core]), "if ($PSVersionTable.PSEdition -eq 'Core') {") || core+1 != create || !strings.HasPrefix(strings.TrimSpace(code[create]), "else {") {
		t.Error("install.ps1: the PowerShell 7 way of creating the folder is not behind the PSEdition test")
	}
}
