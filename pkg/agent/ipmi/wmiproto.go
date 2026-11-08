package ipmi

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
)

// wmiScript runs inside one long-lived powershell.exe: it opens the Microsoft_IPMI WMI class (Windows' built-in
// IPMI driver, ipmidrv.sys, present when the board has a BMC) and answers one request per input line
// "<netfn> <cmd> <b1,b2,...>" with "OK <cc> <hex>" or "ERR <message>". Requests are numbers only (built by
// FormatWMIRequest), so nothing from the network ever becomes PowerShell code.
const wmiScript = `$ErrorActionPreference = 'Stop'
try {
  $ipmi = Get-CimInstance -Namespace 'root/wmi' -ClassName 'Microsoft_IPMI' | Select-Object -First 1
} catch { [Console]::Out.WriteLine('FATAL ' + ($_.Exception.Message -replace '\s+', ' ')); [Console]::Out.Flush(); exit 1 }
if ($null -eq $ipmi) { [Console]::Out.WriteLine('FATAL no Microsoft_IPMI instance (no BMC, or the IPMI driver is not loaded)'); [Console]::Out.Flush(); exit 1 }
[Console]::Out.WriteLine('READY'); [Console]::Out.Flush()
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  $p = $line.Trim().Split(' ')
  try {
    [byte[]]$data = @()
    if ($p.Length -gt 2 -and $p[2] -ne '') { $data = [byte[]]($p[2].Split(',') | ForEach-Object { [byte]$_ }) }
    $send = $data
    if ($data.Length -eq 0) { $send = [byte[]]@(0) }
    $r = Invoke-CimMethod -InputObject $ipmi -MethodName 'RequestResponse' -Arguments @{ NetworkFunction = [byte]$p[0]; LUN = [byte]0; ResponderAddress = [byte]32; Command = [byte]$p[1]; RequestDataSize = [uint32]$data.Length; RequestData = $send }
    $hex = ''
    if ($null -ne $r.ResponseData) { $hex = -join ($r.ResponseData | ForEach-Object { '{0:x2}' -f $_ }) }
    [Console]::Out.WriteLine('OK ' + ('{0:x2}' -f [int]$r.CompletionCode) + ' ' + $hex)
  } catch { [Console]::Out.WriteLine('ERR ' + ($_.Exception.Message -replace '\s+', ' ')) }
  [Console]::Out.Flush()
}
`

// EncodedWMIScript is the script in the form powershell.exe -EncodedCommand expects (base64 of UTF-16LE).
func EncodedWMIScript() string {
	u := utf16.Encode([]rune(wmiScript))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// FormatWMIRequest is one request line for the script.
func FormatWMIRequest(netfn, cmd byte, data []byte) string {
	parts := make([]string, len(data))
	for i, d := range data {
		parts[i] = strconv.Itoa(int(d))
	}
	return strconv.Itoa(int(netfn)) + " " + strconv.Itoa(int(cmd)) + " " + strings.Join(parts, ",") + "\n"
}

// ParseWMIResponse parses one answer line. Microsoft_IPMI's ResponseData starts with the completion code (the
// raw IPMI response), which is dropped here; a non-zero code is a *CompletionError.
func ParseWMIResponse(line string) ([]byte, error) {
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "ERR "):
		return nil, errors.New("IPMI request failed: " + truncate(line[4:], 160))
	case strings.HasPrefix(line, "OK "):
	default:
		return nil, errors.New("unexpected answer from the IPMI helper")
	}
	f := strings.Fields(line[3:])
	if len(f) == 0 {
		return nil, errors.New("unexpected answer from the IPMI helper")
	}
	cc, err := strconv.ParseUint(f[0], 16, 8)
	if err != nil {
		return nil, errors.New("unexpected answer from the IPMI helper")
	}
	if cc != 0 {
		return nil, &CompletionError{Code: byte(cc)}
	}
	var data []byte
	if len(f) > 1 {
		if data, err = hex.DecodeString(f[1]); err != nil {
			return nil, errors.New("unexpected answer from the IPMI helper")
		}
	}
	if len(data) > 0 {
		data = data[1:]
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
