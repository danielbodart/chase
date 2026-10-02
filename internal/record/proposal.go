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
	// Granted are the calls of Allowed the grant allows, which a report
	// tells apart from the tier's.
	Granted map[string]bool
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
		// A recording that refused everything logged none: its filter was
		// the tier's, and what it refuses is no entry.
		if a.Allowed[c.Name] || o.Default == "refuse" {
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
	secret, path := secretIn(l.Path), l.Path
	if secret != "" {
		// The note goes into the checkout's chase.jsonc with the entry.
		path = " a path that may carry a secret, " + secret
	}
	note := fmt.Sprintf("%s %s%s; %s", l.Method, l.Host, path, why(l))
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
	case secret != "":
		p.Left = append(p.Left, Left{l, "its path may carry a secret, " + secret + ", and a grant is committed: name it yourself, with * for that segment"})
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
	secret, command := secretIn(l.Command), l.Command
	if secret != "" {
		// The note goes into the checkout's chase.jsonc with the entry.
		command = "a command that may carry a secret, " + secret
	}
	note := fmt.Sprintf("%s@%s: %s; %s", l.User, l.Address, command, why(l))
	if l.Operation != "" {
		for _, op := range strings.Split(l.Operation, ",") {
			p.add(list, op, note)
		}
		return
	}
	switch {
	case len(l.Command) > maxCommand && strings.HasSuffix(l.Command, "..."):
		// frisket cuts a command it writes down at 4 KiB, ending it
		// "...": a pattern of it would match nothing that ran.
		p.Left = append(p.Left, Left{l, "frisket cut the command short, so it is not one a grant can name exactly"})
	case secret != "":
		p.Left = append(p.Left, Left{l, "it may carry a secret, " + secret + ", and a grant is committed: write its pattern yourself, with * in place of the secret"})
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
// refused by the tier already, and nothing is proposed. A name on the local
// network is never proposed: outside a recording frisket refuses its
// address whatever the allowlist holds.
func (p *Proposal) egress(l Line) {
	if l.Name == "" {
		p.Left = append(p.Left, Left{l, "an address dialled by itself has no name to allow"})
		return
	}
	if l.LAN {
		// frisket's dialer refuses a private address whatever the
		// allowlist says; only a recording dials one, through ClassifyLAN.
		p.Left = append(p.Left, Left{l, "a name on the local network stays refused outside a recording, whatever the allowlist says: no grant entry admits one"})
		return
	}
	note := fmt.Sprintf("port %d; %s", l.Port, why(l))
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
// allow. Syscalls are never asked about -- the filter is fixed before the
// session starts -- so a person's recording, and an ask, allow them; a
// recording that refused everything logs none (Propose).
func (p *Proposal) syscall(c Syscall, o Options) {
	list, note := []string{"seccomp", "allow"}, fmt.Sprintf("logged %d time%s; loosens the tier's filter", c.Count, plural(c.Count))
	switch o.Default {
	case "ask":
		note += "; a syscall cannot be asked about, so this allows it"
	case "":
		note += "; syscalls are not put to you, but allowed and logged while recording"
	}
	if s, ok := highSurface[c.Name]; ok {
		note = "high surface, " + s + ": " + note
	}
	e := Entry{Path: list, Value: c.Name, Note: note}
	if c.Probable {
		e.Off = true
		e.Note = "probable, by when it was made alone: " + note
	}
	p.Entries = append(p.Entries, e)
}

// maxCommand is how much of a command frisket writes down, before the
// "..." it ends one it cut short with.
const maxCommand = 4096

// secretShaped are words that name a secret: one in a flag's name, or in
// a variable's or a header's, carries one.
var secretShaped = []string{"password", "passwd", "passphrase", "token", "secret", "apikey", "api-key", "api_key", "authorization", "credential", "private-key", "private_key"}

// tokenPrefixes begin the tokens of services that mark theirs so.
var tokenPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "sk-", "sk_live_", "AKIA", "ASIA", "AIza", "hf_"}

// secretIn is what in s looks as if it carries a secret, said without
// it, or "": a flag, variable or header named for one (--password,
// DB_TOKEN=, Authorization:), a bearer token, a login in a URL, or a word
// shaped as a token is -- a service's own prefix, or 20 or more letters
// and digits of both cases. A proposal is committed with the checkout, so
// what might be one is never written into it; what it misses is a person's
// to see in the proposal before applying it.
func secretIn(s string) string {
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, `'"`)
		lower := strings.ToLower(w)
		name, _, joined := strings.Cut(lower, "=")
		if !joined {
			name, _, joined = strings.Cut(lower, ":")
		}
		named := slices.ContainsFunc(secretShaped, func(k string) bool { return strings.Contains(name, k) })
		switch {
		case named && (strings.HasPrefix(lower, "-") || joined):
			return "a flag, variable or header named for one"
		case lower == "bearer":
			return "a bearer token"
		case strings.Contains(lower, "://") && strings.Contains(lower[strings.Index(lower, "://")+3:], "@"):
			return "a login in a URL"
		}
		for _, piece := range strings.FieldsFunc(w, func(r rune) bool { return strings.ContainsRune("=:/,;&?@'\"\\", r) }) {
			if slices.ContainsFunc(tokenPrefixes, func(pre string) bool { return strings.HasPrefix(piece, pre) && len(piece) >= len(pre)+16 }) || tokenShaped(piece) {
				return "a word shaped as a token"
			}
		}
	}
	return ""
}

// tokenShaped is whether w is 20 or more of a token's characters, with at
// least two each of upper case, lower case and digits: base64 or base62, as
// a key or a token is, and not a name, a path's word or a hex digest.
func tokenShaped(w string) bool {
	if len(w) < 20 {
		return false
	}
	var upper, lower, digit int
	for _, r := range w {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digit++
		case strings.ContainsRune("+-_.~", r):
		default:
			return false
		}
	}
	return upper >= 2 && lower >= 2 && digit >= 2
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
