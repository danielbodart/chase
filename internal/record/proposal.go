package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/danielbodart/chase/internal/apps/ssh"
	"github.com/danielbodart/chase/internal/term"
)

// A PROPOSAL is what a recording turns into: the grant entries the
// session needed, each exactly what was seen -- an operation's id, or a
// request's method and exact path where no operation was matched; a
// command on a machine, or its catalogue operation; a name; a syscall --
// and each in the list its answer says, `allow`, `ask` or `refuse`. It is
// written in the grant's own shape, as JSONC, with what each entry was
// made from beside it; `chase record apply` adds each to the checkout's
// chase.jsonc, and the changed grant is approved at the next launch as any
// change is. Nothing is generalised: a person widens an entry, if they
// want to, by editing it.
//
// What was answered and cannot be a grant entry -- a route no grant has
// lists for, a machine that is the tier's own, a refusal of a name -- is
// left out and said why (Left).

// Options are how a recording was made: `chase record`'s --default, ""
// for a person's answers, and --base.
type Options struct {
	Default string `json:"default"`
	Base    string `json:"base"`
}

// Against is what the proposal is made against: the machines the
// checkout's grant names, which alone take its lists, and the calls already
// allowed -- the grant's, and for a recording from scratch, which logs
// every call, the tier's -- which it does not propose again.
type Against struct {
	Hosts   map[string]bool
	Allowed map[string]bool
}

// Entry is one entry for a grant list: Path is the list, as the grant
// nests it (apps, github, allow); Value a string or an endpoint; Note what
// it was made from, a comment beside it; and Off an entry written as a
// comment, never applied unless a person uncomments it.
type Entry struct {
	Path  []string
	Value any
	Note  string
	Off   bool
}

// endpoint is a list entry for a request no operation matched, as a grant
// names one.
type endpoint struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

// Left is something answered that no grant entry can be: the line, and
// why.
type Left struct {
	Line Line
	Why  string
}

// Proposal is the entries a recording proposes, and what it leaves out.
type Proposal struct {
	Entries []Entry
	Left    []Left
}

// grantApps are the apps whose lists a grant has, by their route's name,
// as the launch applies them (internal/grant's applyLists).
var grantApps = []string{"cloudflare", "gcloud", "git", "github", "huggingface"}

// highSurface are calls a grant may allow and a person should know they
// allow: each a large piece of kernel reached from the session, and not
// gated by a capability on a host as this one is set up.
var highSurface = map[string]string{
	"io_uring_setup": "io_uring", "io_uring_enter": "io_uring", "io_uring_register": "io_uring",
	"keyctl": "the kernel's keyrings", "add_key": "the kernel's keyrings", "request_key": "the kernel's keyrings",
	"userfaultfd":     "userfaultfd",
	"bpf":             "BPF",
	"perf_event_open": "perf events",
}

// rank orders answers from the most to the least permissive.
func rank(answer string) int { return slices.Index([]string{"allow", "ask", "refuse"}, answer) }

// loosens is whether answering a with what the policy would do, would,
// lets through more than the tier did.
func loosens(answer, would string) bool { return rank(answer) >= 0 && rank(answer) < rank(would) }

// Propose is the entries lines and calls make, as o recorded them, against
// a.
func Propose(lines []Line, calls []Syscall, o Options, a Against) Proposal {
	var p Proposal
	var answered []Line
	for _, l := range lines {
		if l.answered() && l.Kind != "dns" {
			answered = append(answered, l)
		}
	}
	for _, l := range latest(answered) {
		if rank(l.Answer) < 0 {
			p.Left = append(p.Left, Left{l, fmt.Sprintf("%q is not an answer", l.Answer)})
			continue
		}
		switch l.Kind {
		case "http":
			p.http(l)
		case "ssh":
			p.ssh(l, a)
		case "egress":
			p.egress(l)
		default:
			p.Left = append(p.Left, Left{l, "not a kind a grant has entries for"})
		}
	}
	for _, c := range calls {
		if a.Allowed[c.Name] {
			continue
		}
		p.syscall(c, o)
	}
	return p
}

// why is what the policy would have done, and by which rule.
func why(l Line) string {
	s := "the tier would " + l.Would
	if l.Rule != "" {
		s += " (" + l.Rule + ")"
	}
	if loosens(l.Answer, l.Would) {
		s = "loosens: " + s
	}
	if l.Source == "human" {
		s += "; answered " + l.Answer
	}
	return s
}

func (p *Proposal) add(path []string, v any, note string) {
	p.Entries = append(p.Entries, Entry{Path: path, Value: v, Note: note})
}

// http is a request on a route: the app's list, by the operation each id
// the request matched names, or by its method and path where it matched
// none.
func (p *Proposal) http(l Line) {
	if !slices.Contains(grantApps, l.Route) {
		p.Left = append(p.Left, Left{l, fmt.Sprintf("a grant has no lists for the %s route", l.Route)})
		return
	}
	list := []string{"apps", l.Route, l.Answer}
	note := fmt.Sprintf("%s %s%s; %s", l.Method, l.Host, l.Path, why(l))
	if l.Operation != "" {
		for _, op := range strings.Split(l.Operation, ",") {
			p.add(list, op, note)
		}
		return
	}
	switch {
	case l.GraphQL != "":
		p.Left = append(p.Left, Left{l, "a GraphQL request that matched no operation has no entry"})
	case !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}, l.Method):
		p.Left = append(p.Left, Left{l, fmt.Sprintf("%s is not a method a grant names", l.Method)})
	case !strings.HasPrefix(l.Path, "/") || strings.ContainsAny(l.Path, " \t\r\n*") || strings.HasSuffix(l.Path, "..."):
		// A * in an endpoint's path is any segment, and frisket cuts a
		// path it writes down at 2 KiB, ending it "...".
		p.Left = append(p.Left, Left{l, "its path is not one a grant can name exactly"})
	default:
		p.add(list, endpoint{Methods: []string{l.Method}, Path: l.Path}, note)
	}
}

// ssh is a command on a machine the grant names: that machine's list, by
// the catalogue operation it matched, or by the command itself as a
// pattern, which matches it alone. A command with a `*` in it would be a
// wider pattern than what was seen, and a one-word command is no pattern
// at all -- a grant reads a word with no space as an operation's id -- so
// neither is proposed. A machine the grant does not name is the tier's
// own, whose lists are its configuration's.
func (p *Proposal) ssh(l Line, a Against) {
	if !a.Hosts[l.Route] {
		p.Left = append(p.Left, Left{l, fmt.Sprintf("%s is not a machine the grant names: its lists are the tier's", l.Route)})
		return
	}
	list := []string{"apps", "ssh", "hosts", l.Route, l.Answer}
	note := fmt.Sprintf("%s@%s: %s; %s", l.User, l.Address, l.Command, why(l))
	if l.Operation != "" {
		for _, op := range strings.Split(l.Operation, ",") {
			p.add(list, op, note)
		}
		return
	}
	switch {
	case strings.Contains(l.Command, "*"):
		p.Left = append(p.Left, Left{l, "a command with a * would be a wider pattern than what ran"})
	case !strings.Contains(l.Command, " "):
		p.Left = append(p.Left, Left{l, "a one-word command is no pattern a grant reads; name its operation, or the command with ** after it"})
	default:
		if err := ssh.CheckPattern(l.Command); err != nil {
			p.Left = append(p.Left, Left{l, err.Error()})
			return
		}
		p.add(list, l.Command, note)
	}
}

// egress is a connection to a name no route serves: the grant's network,
// by the name, which frisket's allowlist holds without a port. A name is
// allowed or not: one answered ask is allowed, and said so; one refused is
// refused by the tier already, and nothing is proposed.
func (p *Proposal) egress(l Line) {
	if l.Name == "" {
		p.Left = append(p.Left, Left{l, "an address dialled by itself has no name to allow"})
		return
	}
	note := fmt.Sprintf("port %d", l.Port)
	if l.LAN {
		note += ", on the local network"
	}
	note += "; " + why(l)
	switch l.Answer {
	case "refuse":
		p.Left = append(p.Left, Left{l, "a name off the allowlist is refused already: a grant only adds names"})
		return
	case "ask":
		note += ": a name cannot be asked about, so this allows it"
	}
	p.add([]string{"network", "allow"}, l.Name, note)
}

// syscall is a call the filter would have refused: the grant's seccomp
// allow, or its deny for a recording that refused everything. Syscalls are
// never asked about -- the filter is fixed before the session starts -- so
// a person's recording, and an ask, allow them.
func (p *Proposal) syscall(c Syscall, o Options) {
	list, note := []string{"seccomp", "allow"}, fmt.Sprintf("logged %d time%s; loosens the tier's filter", c.Count, plural(c.Count))
	switch o.Default {
	case "refuse":
		list, note = []string{"seccomp", "deny"}, fmt.Sprintf("logged %d time%s; the tier refuses it already", c.Count, plural(c.Count))
	case "ask":
		note += "; a syscall cannot be asked about, so this allows it"
	case "":
		note += "; syscalls are not put to you, but allowed and logged while recording"
	}
	if s, ok := highSurface[c.Name]; ok && list[1] == "allow" {
		note = "high surface, " + s + ": " + note
	}
	e := Entry{Path: list, Value: c.Name, Note: note}
	if c.Probable {
		e.Off = true
		e.Note = "probable, by when it was made alone: " + note
	}
	p.Entries = append(p.Entries, e)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// comment is s as one line of a // comment: cleaned of what a terminal
// would act on, as everything chase shows is, and its line breaks spaces.
func comment(s string) string {
	return strings.ReplaceAll(term.Clean(s), "\n", " ")
}

// JSONC is the proposal as the file `chase record apply` reads: header,
// each line a comment, then the entries nested as the grant nests them,
// each with its note on the line above it. Keys are in order; entries in
// the order they were proposed, each once.
func (p Proposal) JSONC(header []string) []byte {
	var b bytes.Buffer
	for _, h := range header {
		b.WriteString("// " + comment(h) + "\n")
	}
	root := &node{}
	for _, e := range p.Entries {
		root.at(e.Path).items = append(root.at(e.Path).items, e)
	}
	if len(root.keys) == 0 {
		b.WriteString("{}\n")
		return b.Bytes()
	}
	root.write(&b, 0)
	b.WriteString("\n")
	return b.Bytes()
}

// node is one object of the proposal, or, with items, one list.
type node struct {
	keys  []string
	kids  map[string]*node
	items []Entry
}

func (n *node) at(path []string) *node {
	for _, k := range path {
		if n.kids == nil {
			n.kids = map[string]*node{}
		}
		kid, ok := n.kids[k]
		if !ok {
			kid = &node{}
			n.kids[k] = kid
			n.keys = append(n.keys, k)
		}
		n = kid
	}
	return n
}

func (n *node) write(b *bytes.Buffer, depth int) {
	in := strings.Repeat("  ", depth+1)
	if n.kids == nil {
		b.WriteString("[\n")
		seen := map[string]bool{}
		for _, e := range n.items {
			v := marshal(e.Value)
			if seen[string(v)] {
				continue
			}
			seen[string(v)] = true
			if e.Note != "" {
				b.WriteString(in + "// " + comment(e.Note) + "\n")
			}
			if e.Off {
				b.WriteString(in + "// ")
			} else {
				b.WriteString(in)
			}
			b.Write(v)
			b.WriteString(",\n")
		}
		b.WriteString(strings.Repeat("  ", depth) + "]")
		return
	}
	b.WriteString("{\n")
	keys := slices.Clone(n.keys)
	slices.Sort(keys)
	for _, k := range keys {
		q := marshal(k)
		b.WriteString(in)
		b.Write(q)
		b.WriteString(": ")
		n.kids[k].write(b, depth+1)
		b.WriteString(",\n")
	}
	b.WriteString(strings.Repeat("  ", depth) + "}")
}

// marshal is v as JSON, with what HTML would read left as it is: a
// command's && is a command's, not \u0026\u0026.
func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
