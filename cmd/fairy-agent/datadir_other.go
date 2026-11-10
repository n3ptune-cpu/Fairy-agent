//go:build !windows

package main

// The data folder checks of datadir.go are for Windows (C:\ProgramData\fairy-agent, where ordinary users may
// create things). On Linux /etc/fairy-agent belongs to root and the package's files have fixed modes.

// dataDirTrusted is checked by join before it writes anything, and by the commands an administrator types
// (adminDataDirTrusted); tests replace it.
var dataDirTrusted = func(string) error { return nil }

// updateDirTrusted is the Windows check before apply-update reads or opens anything; tests replace it.
var updateDirTrusted = func(string) error { return nil }

// tokensInConfigDir: join writes token files only into the config folder (Windows). Elsewhere config.yaml may
// name them anywhere, as before.
var tokensInConfigDir = false
