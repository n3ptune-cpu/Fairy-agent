package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// UninstallMarker is the one-time request the Windows helper leaves for the updater service after it has
// verified an uninstall's passkey approval itself (POST /uninstall → helper verb uninstall → updater).
//
// It lives in the helper's folder, next to the trust file: a folder that only administrators and SYSTEM can
// change, which CheckDir verifies (owner and permission list) every time before the file is written or read,
// and the file itself must pass CheckFile. The agent's account can read that folder and nothing more, so it
// cannot leave such a request; the stage folder the agent may write is never looked at for this. The updater
// takes the file away before it does anything (Take), so one request is acted on once, and a request older than
// UninstallMarkerTTL, or from the future, is taken away and not acted on.
type UninstallMarker struct {
	Path      string
	CheckDir  func(dir string) error  // Windows: collect.TrustedFolder
	CheckFile func(path string) error // Windows: collect.TrustedFile
}

// UninstallMarkerName is the file's name in the helper's folder.
const UninstallMarkerName = "uninstall-request.json"

// UninstallMarkerTTL is how long after the helper wrote it the updater still acts on the request. The helper
// starts the updater right after writing it, so this is only the time Windows takes to start a service.
const UninstallMarkerTTL = 2 * time.Minute

// uninstallMarkerSkew is how far in this machine's future a request's time may be (two processes on one clock).
const uninstallMarkerSkew = 30 * time.Second

const uninstallMarkerMax = 1024

type uninstallRequest struct {
	V  int    `json:"v"`
	At int64  `json:"at"` // unix seconds, the helper's clock when it wrote the file
	By string `json:"by"` // who asked, as the helper's audit log names it
}

// ErrUpdaterBusy: the Windows updater service is running (an update): an uninstall is not started behind it.
var ErrUpdaterBusy = errors.New("the fairy-agent-update service is running (an update?): try again when it is done")

// ErrNoUninstallMarker: there is no request (the usual case: the updater was started for an update).
var ErrNoUninstallMarker = errors.New("no uninstall request")

func (m UninstallMarker) checkDir() error {
	if m.CheckDir == nil {
		return nil
	}
	if err := m.CheckDir(filepath.Dir(m.Path)); err != nil {
		return fmt.Errorf("the folder of the uninstall request is not safe: %w", err)
	}
	return nil
}

// Write leaves the request, replacing an older one. Only the helper calls it, after the approval was accepted.
func (m UninstallMarker) Write(by string, now time.Time) error {
	if err := m.checkDir(); err != nil {
		return err
	}
	b, err := json.Marshal(uninstallRequest{V: 1, At: now.Unix(), By: by})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.Path), ".uninstall-*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), m.Path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// Remove takes the request away without reading it (the helper, when the updater could not be started).
func (m UninstallMarker) Remove() error {
	err := os.Remove(m.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Take reads the request and takes it away, in that order, before the caller does anything: whatever happens
// next, it is never acted on twice. It returns who asked. ErrNoUninstallMarker: there is none. Any other error
// means "do not uninstall": the folder or the file is not what the helper makes (it is then left where it is
// for an administrator to look at, unless it could be read, in which case it is removed), it is not a request,
// or it is not fresh.
func (m UninstallMarker) Take(now time.Time) (by string, err error) {
	if _, err := os.Lstat(m.Path); errors.Is(err, os.ErrNotExist) {
		return "", ErrNoUninstallMarker
	} else if err != nil {
		return "", err
	}
	if err := m.checkDir(); err != nil {
		return "", err
	}
	st, err := os.Lstat(m.Path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a plain file: not acted on", m.Path)
	}
	if m.CheckFile != nil {
		if err := m.CheckFile(m.Path); err != nil {
			return "", fmt.Errorf("the uninstall request is not safe, not acted on: %w", err)
		}
	}
	f, err := os.Open(m.Path)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, uninstallMarkerMax+1))
	f.Close()
	if err != nil {
		return "", err
	}
	if err := os.Remove(m.Path); err != nil { // used up before anything is done
		return "", fmt.Errorf("the uninstall request could not be taken away, so it is not acted on: %w", err)
	}
	var r uninstallRequest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if len(b) > uninstallMarkerMax || dec.Decode(&r) != nil || dec.More() || r.V != 1 || r.At <= 0 {
		return "", errors.New("the uninstall request is not one the helper writes: not acted on")
	}
	at := time.Unix(r.At, 0)
	if at.After(now.Add(uninstallMarkerSkew)) || now.Sub(at) > UninstallMarkerTTL {
		return "", fmt.Errorf("the uninstall request is from %s, not from the last %s: not acted on", at.UTC().Format(time.RFC3339), UninstallMarkerTTL)
	}
	return r.By, nil
}
