package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/danielbodart/chase/internal/files"
)

// WHAT A RECORDING LEAVES is a directory of its own under the user's
// state, ~/.local/state/chase/records/<machine>, which no session sees:
//
//	record.jsonl    every line the recording wrote down -- frisket's, and
//	                one of chase's own for each syscall
//	meta.json       which session, tier and checkout, how it was made, and
//	                when
//	proposal.jsonc  the grant entries it proposes, which `chase record
//	                apply` adds to the checkout's chase.jsonc
//
// The last Keep recordings are kept, and any younger than KeepFor: a
// recording is pruned only once it is both older and further back.
const (
	Keep    = 20
	KeepFor = 14 * 24 * time.Hour
)

// Meta is a recording's meta.json.
type Meta struct {
	Machine   string    `json:"machine"`
	Tier      string    `json:"tier"`
	Workspace string    `json:"workspace"`
	Agent     string    `json:"agent"`
	Options   Options   `json:"options"`
	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended"`
	// Exit is the session's status, as the launcher exited with it.
	Exit int `json:"exit"`
	// Sole is whether no other recording ran beside it, so that a call
	// made by a process gone too soon to place was put down to it by time.
	Sole bool `json:"sole"`
	// Applied is when `chase record apply` last merged its proposal.
	Applied *time.Time `json:"applied,omitempty"`
}

// Files of a recording's directory.
const (
	recordFile   = "record.jsonl"
	metaFile     = "meta.json"
	proposalFile = "proposal.jsonc"
)

// save writes a recording's directory under dir, whole: its lines, its
// meta, and its proposal.
func save(dir string, m Meta, lines []Line, proposal []byte) (string, error) {
	at := filepath.Join(dir, m.Machine)
	if err := os.MkdirAll(at, 0o700); err != nil {
		return "", err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	for _, l := range lines {
		if err := enc.Encode(l); err != nil {
			return "", err
		}
	}
	if err := files.WriteAtomic(filepath.Join(at, recordFile), b.Bytes(), 0o600); err != nil {
		return "", err
	}
	if err := writeMeta(at, m); err != nil {
		return "", err
	}
	return at, files.WriteAtomic(filepath.Join(at, proposalFile), proposal, 0o600)
}

func writeMeta(at string, m Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return files.WriteAtomic(filepath.Join(at, metaFile), append(b, '\n'), 0o600)
}

func readMeta(at string) (Meta, error) {
	b, err := os.ReadFile(filepath.Join(at, metaFile))
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Meta{}, fmt.Errorf("%s: %w", filepath.Join(at, metaFile), err)
	}
	return m, nil
}

// recordings is every recording under dir with a meta.json, newest first.
func recordings(dir string) ([]Meta, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := readMeta(filepath.Join(dir, e.Name()))
		if err != nil || m.Machine != e.Name() {
			continue
		}
		out = append(out, m)
	}
	slices.SortStableFunc(out, func(a, b Meta) int { return b.Ended.Compare(a.Ended) })
	return out, nil
}

// Prune removes each recording under dir beyond the newest keep that is
// older than keepFor at now, and is the machines it removed.
func Prune(dir string, now time.Time, keep int, keepFor time.Duration) []string {
	all, err := recordings(dir)
	if err != nil {
		return nil
	}
	var gone []string
	for i, m := range all {
		if i < keep || now.Sub(m.Ended) < keepFor {
			continue
		}
		if os.RemoveAll(filepath.Join(dir, m.Machine)) == nil {
			gone = append(gone, m.Machine)
		}
	}
	return gone
}

// find is the recording under dir that which names: "--last" or "" for
// the newest, or a machine's name.
func find(dir, which string) (string, Meta, error) {
	if which == "" || which == "--last" {
		all, err := recordings(dir)
		if err != nil {
			return "", Meta{}, err
		}
		if len(all) == 0 {
			return "", Meta{}, errors.New("there is no recording")
		}
		return filepath.Join(dir, all[0].Machine), all[0], nil
	}
	if which == "." || which == ".." || strings.ContainsAny(which, "/\x00") || strings.HasPrefix(which, ".") {
		return "", Meta{}, fmt.Errorf("%q is not a session's name", which)
	}
	at := filepath.Join(dir, which)
	m, err := readMeta(at)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", Meta{}, fmt.Errorf("there is no recording of %s", which)
		}
		return "", Meta{}, err
	}
	return at, m, nil
}
