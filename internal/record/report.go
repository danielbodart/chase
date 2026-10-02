package record

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/danielbodart/chase/internal/term"
)

// Report is what `chase record` says once the session ends: what was
// answered, by kind; the names resolved; the syscalls; what was refused
// that no grant can change, and what went unanswered; what could not be
// proposed, and why; and where the proposal is, with what it would change.
type Report struct {
	Meta     Meta
	Lines    []Line
	Calls    []Syscall
	Proposal Proposal
	// Elsewhere and Unsure are the logged calls put down to another
	// process, and those placed nowhere.
	Elsewhere, Unsure int
	// Notes are what went wrong on the way, or is worth knowing.
	Notes []string
	// Dir is where the recording is kept; Diff what applying the
	// proposal would do to the checkout's chase.jsonc.
	Dir  string
	Diff string
}

// Write says r to w, every byte of it through term.Clean: a path, a
// command and a name are what the session sent.
func (r Report) Write(w io.Writer) {
	var b strings.Builder
	m := r.Meta
	how := "a person's answers"
	if m.Options.Default != "" {
		how = "--default " + m.Options.Default
	}
	fmt.Fprintf(&b, "chase: recorded %s, %s in %s, with %s and --base %s: %s, exited %d\n",
		m.Machine, m.Tier, m.Workspace, how, m.Options.Base, m.Ended.Sub(m.Started).Round(time.Second), m.Exit)

	var answered, hard, unanswered, dns []Line
	for _, l := range r.Lines {
		switch {
		case l.Kind == "dns":
			dns = append(dns, l)
		case l.answered():
			answered = append(answered, l)
		case l.Source == "hard":
			hard = append(hard, l)
		case l.Source == "unanswered":
			unanswered = append(unanswered, l)
		}
	}
	answered = latest(answered)
	section := func(title string, rows []string) {
		if len(rows) == 0 {
			return
		}
		b.WriteString("\n" + title + "\n")
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, row := range rows {
			fmt.Fprintln(tw, "  "+row)
		}
		tw.Flush()
	}
	rows := func(kind string, of func(Line) string) []string {
		var out []string
		for _, l := range answered {
			if l.Kind == kind {
				out = append(out, l.Answer+"\t"+of(l)+"\t"+would(l))
			}
		}
		return out
	}
	section("HTTP on routes", rows("http", func(l Line) string {
		s := l.Route + "\t" + l.Method + " " + l.Host + l.Path
		if l.Operation != "" {
			s += "\t" + l.Operation
		} else {
			s += "\t" + l.GraphQL
		}
		return s
	}))
	section("SSH", rows("ssh", func(l Line) string {
		return l.Route + "\t" + l.User + "@" + l.Address + "\t" + l.Command
	}))
	section("Egress", rows("egress", func(l Line) string {
		s := fmt.Sprintf("%s:%d\t%s", l.Name, l.Port, l.Address)
		if l.LAN {
			s += " (local network)"
		}
		return s
	}))
	var names []string
	seen := map[string]bool{}
	for _, l := range dns {
		if !seen[l.Name] {
			seen[l.Name] = true
			names = append(names, l.Name)
		}
	}
	section("DNS names resolved off the allowlist", names)
	// From scratch, every call is logged: those the tier allows already are
	// the session's mould, said as the tier's, and not proposed.
	proposed := map[string]bool{}
	for _, e := range r.Proposal.Entries {
		if n, ok := e.Value.(string); ok && e.Path[0] == "seccomp" {
			proposed[n] = true
		}
	}
	scratch := m.Options.Base == "none"
	var calls []string
	for _, c := range r.Calls {
		s := fmt.Sprintf("%s\t%d time%s", c.Name, c.Count, plural(c.Count))
		switch {
		case scratch && !proposed[c.Name]:
			s += "\tthe tier's"
		case c.Probable:
			s += "\tprobable: placed by when it was made alone"
		}
		calls = append(calls, s)
	}
	if scratch {
		section("Syscalls the session made, but those every process makes", calls)
	} else {
		section("Syscalls the filter would have refused", calls)
	}
	var refused []string
	for _, l := range latest(hard) {
		refused = append(refused, l.Kind+"\t"+what(l)+"\t"+l.Reason)
	}
	section("Refused, and no grant changes it", refused)
	var left []string
	for _, l := range latest(unanswered) {
		left = append(left, l.Kind+"\t"+what(l)+"\t"+l.Reason)
	}
	section("Refused for want of an answer", left)
	var unproposed []string
	for _, l := range r.Proposal.Left {
		unproposed = append(unproposed, l.Line.Kind+"\t"+what(l.Line)+"\t"+l.Why)
	}
	section("Answered, and not proposed", unproposed)
	notes := r.Notes
	if r.Elsewhere > 0 {
		notes = append(notes, fmt.Sprintf("%d logged call%s by other processes left out", r.Elsewhere, plural(r.Elsewhere)))
	}
	if r.Unsure > 0 {
		notes = append(notes, fmt.Sprintf("%d logged call%s by processes gone before they could be placed left out", r.Unsure, plural(r.Unsure)))
	}
	section("Notes", notes)

	b.WriteString("\n")
	if len(r.Proposal.Entries) == 0 {
		fmt.Fprintf(&b, "Nothing to propose. The recording is in %s\n", r.Dir)
	} else {
		fmt.Fprintf(&b, "Proposed, in %s/%s:\n", r.Dir, proposalFile)
		if r.Diff != "" {
			b.WriteString(r.Diff)
			if !strings.HasSuffix(r.Diff, "\n") {
				b.WriteString("\n")
			}
		}
		fmt.Fprintf(&b, "Add it to %s/chase.jsonc with: chase record apply %s\n", m.Workspace, m.Machine)
	}
	io.WriteString(w, term.Clean(b.String()))
}

// would is what the policy would have done with l, and by which rule.
func would(l Line) string {
	s := "would " + l.Would
	if l.Rule != "" {
		s += ": " + l.Rule
	}
	if l.Source == "human" {
		s += ", answered by you"
	}
	return s
}

// what is what l was about, in a few words.
func what(l Line) string {
	switch l.Kind {
	case "http":
		return l.Route + " " + l.Method + " " + l.Host + l.Path
	case "ssh":
		return l.Route + " " + l.Command
	case "egress":
		if l.Name == "" {
			return l.Address
		}
		return fmt.Sprintf("%s:%d", l.Name, l.Port)
	}
	return l.Name
}
