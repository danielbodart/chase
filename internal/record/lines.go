package record

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Line is one line of what a recording session wrote down: frisket's, as
// its sink and its journal hold them (frisket's docs/record.md, "The
// lines"), and chase's own for a syscall, which frisket never sees, kind
// "syscall". What a grant entry is made from is a line whose source is
// "default" or "human": what was answered, and by whom.
type Line struct {
	Time    time.Time `json:"time,omitzero"`
	Session string    `json:"session,omitempty"`
	Policy  string    `json:"policy,omitempty"`
	// Kind is "http", "ssh", "egress", "dns" or, chase's own, "syscall".
	Kind      string `json:"kind"`
	Route     string `json:"route,omitempty"`
	Method    string `json:"method,omitempty"`
	Host      string `json:"host,omitempty"`
	Path      string `json:"path,omitempty"`
	Name      string `json:"name,omitempty"`
	Port      int    `json:"port,omitempty"`
	Address   string `json:"address,omitempty"`
	User      string `json:"user,omitempty"`
	Command   string `json:"command,omitempty"`
	Shell     bool   `json:"shell,omitempty"`
	LAN       bool   `json:"lan,omitempty"`
	Operation string `json:"operation,omitempty"`
	GraphQL   string `json:"graphql,omitempty"`
	// Would is what the policy would have done: "refuse" or "ask".
	Would string `json:"would,omitempty"`
	Rule  string `json:"rule,omitempty"`
	// Answer is "allow", "ask" or "refuse": what happened, and what is
	// written down.
	Answer string `json:"answer,omitempty"`
	// Source is "default", "human", "unanswered", "hard" or "telemetry".
	Source string `json:"source,omitempty"`
	Reason string `json:"reason,omitempty"`

	// Count is how many times a syscall was logged, and Probable whether
	// it was put down to the session only by when it was made (Attribute).
	Count    int  `json:"count,omitempty"`
	Probable bool `json:"probable,omitempty"`

	// Truncated is the one line a full sink ends with.
	Truncated bool `json:"truncated,omitempty"`
}

// Sources a grant entry comes of: an answer someone gave.
func (l Line) answered() bool { return l.Source == "default" || l.Source == "human" }

// subject is what frisket decides once a session, as its own memo keys
// it, so that the last answer for one is the one that stands: an
// operation, or a request's exact path, on a route; a command on a
// machine; a name and port, or the address dialled where there was no
// name; a name.
func (l Line) subject() string {
	switch l.Kind {
	case "http":
		if l.Operation != "" {
			return l.Kind + "\x00" + l.Route + "\x00" + l.Method + "\x00op\x00" + l.Operation + "\x00" + l.GraphQL
		}
		return l.Kind + "\x00" + l.Route + "\x00" + l.Method + "\x00path\x00" + l.Path + "\x00" + l.GraphQL
	case "ssh":
		return l.Kind + "\x00" + l.Route + "\x00" + l.Command
	case "egress":
		if l.Name == "" {
			return l.Kind + "\x00address\x00" + l.Address
		}
		return l.Kind + "\x00" + l.Name + "\x00" + strconv.Itoa(l.Port) + "\x00" + strconv.FormatBool(l.LAN)
	}
	return l.Kind + "\x00" + l.Name
}

// maxLine is the longest line read back: frisket bounds a path at 2 KiB
// and a command at 4 KiB, so anything near this is not one of its lines.
const maxLine = 64 << 10

// ReadLines is the lines of r that are session's, or every one when
// session is "": what a sink holds, one JSON object a line. A line that is
// not one of frisket's is skipped and counted; a sink that filled says so
// in its last line, which is not returned.
func ReadLines(r io.Reader, session string) (lines []Line, skipped int, truncated bool, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var l Line
		if json.Unmarshal(b, &l) != nil {
			skipped++
			continue
		}
		switch {
		case l.Truncated:
			truncated = true
		case l.Kind == "":
			skipped++
		case session == "" || l.Session == session:
			lines = append(lines, l)
		}
	}
	return lines, skipped, truncated, sc.Err()
}

// readSink is the session's lines from frisket's sink at path.
func readSink(path, session string) ([]Line, int, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, false, err
	}
	defer f.Close()
	return ReadLines(f, session)
}

// journalLine is a frisket log line: slog's JSON, its message, and a
// record line's fields beside it.
type journalLine struct {
	Msg string `json:"msg"`
	Line
}

// ReadJournal is the session's record lines from frisket's own log, for
// when its sink cannot be read: each journal message frisket wrote that is
// a "record" line of the session's. The journal rate-limits, so this may
// be less than the sink would have been.
func ReadJournal(r io.Reader, session string) []Line {
	var out []Line
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		var j journalLine
		if json.Unmarshal(sc.Bytes(), &j) != nil || j.Msg != "record" || j.Session != session || j.Kind == "" {
			continue
		}
		out = append(out, j.Line)
	}
	return out
}

// journalRecords is ReadJournal of frisket's unit's messages since since,
// as journalctl prints them.
func journalRecords(ctx context.Context, journalctl string, since time.Time, session string) ([]Line, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, journalctl, "--no-pager", "-o", "cat",
		fmt.Sprintf("--since=@%d", since.Unix()), "_SYSTEMD_UNIT=frisket.service")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	lines := ReadJournal(&out, session)
	if len(lines) == 0 {
		return nil, errors.New("frisket's journal has no record line of the session")
	}
	return lines, nil
}

// latest is lines with only the last of each subject's: a person asked
// again, or a refusal for want of an answer then answered, is what was
// answered last.
func latest(lines []Line) []Line {
	at := map[string]int{}
	var out []Line
	for _, l := range lines {
		k := l.subject()
		if i, ok := at[k]; ok {
			out[i] = l
			continue
		}
		at[k] = len(out)
		out = append(out, l)
	}
	return out
}
