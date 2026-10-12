package record

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/frisket/projpolicy"

	"github.com/danielbodart/chase/internal/apps/ssh"
	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/term"
)

// A PROPOSAL is what a recording turns into: the entries of the
// checkout's chase.json the session needed, each exactly what was seen --
// an operation's id, or a request's method and exact path where no
// operation was matched, answered in its route's operations; a command on
// a machine, or its catalogue operation, in the machine's list its answer
// says, `allow`, `ask` or `refuse`; a name; a syscall. It is written in
// chase.json's own shape, as strict JSON, beside what each entry was made
// from; `chase record apply` adds each to the checkout's chase.json and
// signs it. Nothing is generalised: a person widens an entry, if they
// want to, by editing it.
//
// What was answered and cannot be an entry -- a route no project answers,
// a machine that is the tier's own, a refusal of a name -- is left out and
// said why (Left). A name on the local network, answered allow or ask, is
// a frisket.lan entry with the ports it was dialled at, and on the
// allowlist.

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

// Entry is one entry of a chase.json: Path is the object or list it goes
// in, as the file nests it (frisket, routes, github, operations); Key its
// key there, or "" in a list; Value what it is; Note what it was made from,
// kept beside the proposal; and Off an entry proposed only as probable,
// never applied unless a person moves it into what is proposed.
type Entry struct {
	Path  []string
	Key   string
	Value any
	Note  string
	Off   bool
}

// at is where e is in the file, a key at a time.
func (e Entry) at() []string {
	if e.Key == "" {
		return e.Path
	}
	return append(slices.Clone(e.Path), e.Key)
}

// pointer is a JSON pointer to e, RFC 6901's.
func (e Entry) pointer() string {
	var b strings.Builder
	for _, k := range e.at() {
		b.WriteString("/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(k))
	}
	return b.String()
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

// grantApps are the routes a project's frisket section answers, by name,
// as the module has them (grant.nix's answerable).
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

func (p *Proposal) add(path []string, key string, v any, note string) {
	p.Entries = append(p.Entries, Entry{Path: path, Key: key, Value: v, Note: note})
}

// http is a request on a route: the route's operations, by the id of each
// operation the request matched, or by its method and path where it
// matched none, answered as it was.
func (p *Proposal) http(l Line) {
	if !slices.Contains(grantApps, l.Route) {
		p.Left = append(p.Left, Left{l, fmt.Sprintf("a project answers none of the %s route's requests", l.Route)})
		return
	}
	ops := []string{"frisket", "routes", l.Route, "operations"}
	secret, path := secretIn(l.Path), l.Path
	if secret != "" {
		// The note goes into the proposal with the entry.
		path = " a path that may carry a secret, " + secret
	}
	note := fmt.Sprintf("%s %s%s; %s", l.Method, l.Host, path, why(l))
	if l.Operation != "" {
		for _, op := range strings.Split(l.Operation, ",") {
			p.add(ops, op, l.Answer, note)
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
		p.add(ops, l.Method+" "+l.Path, l.Answer, note)
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
	list := []string{"chase", "apps", "ssh", "hosts", l.Route, l.Answer}
	secret, command := secretIn(l.Command), l.Command
	if secret != "" {
		// The note goes into the proposal with the entry.
		command = "a command that may carry a secret, " + secret
	}
	note := fmt.Sprintf("%s@%s: %s; %s", l.User, l.Address, command, why(l))
	if l.Operation != "" {
		for _, op := range strings.Split(l.Operation, ",") {
			p.add(list, "", op, note)
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
		p.add(list, "", l.Command, note)
	}
}

// egress is a connection to a name no route serves: frisket's allowlist,
// by the name, which it holds without a port. A name is allowed or not:
// one answered ask is allowed, and said so; one refused is refused by the
// tier already, and nothing is proposed. A name whose address is on the
// local network, which frisket refuses outside a recording whatever the
// allowlist holds, is frisket.lan's too, with the ports it was dialled at
// (lan).
func (p *Proposal) egress(l Line) {
	if l.Name == "" {
		p.Left = append(p.Left, Left{l, "an address dialled by itself has no name to allow"})
		return
	}
	if l.Answer == "refuse" {
		p.Left = append(p.Left, Left{l, "a name off the allowlist is refused already: a grant only adds names"})
		return
	}
	if l.LAN {
		p.lan(l)
		return
	}
	note := fmt.Sprintf("port %d; %s", l.Port, why(l))
	if l.Answer == "ask" {
		note += ": a name cannot be asked about, so this allows it"
	}
	p.add(allowPath, l.Name, true, note)
}

// allowPath and lanPath are where a name goes in a chase.json.
var (
	allowPath = []string{"frisket", "allow"}
	lanPath   = []string{"frisket", "lan"}
)

// lan is a name on the local network, answered allow or ask: one
// frisket.lan entry for the name, holding every port it was dialled at,
// and the name on the allowlist, which frisket reaches it only through. A
// name frisket would not take in its lan list -- a project's own,
// frisket's -- is left out.
func (p *Proposal) lan(l Line) {
	if err := grant.CheckLAN([]policy.LANHost{{Name: l.Name, Ports: []int{l.Port}}}); err != nil {
		p.Left = append(p.Left, Left{l, err.Error()})
		return
	}
	note := fmt.Sprintf("on the local network, port %d; %s", l.Port, why(l))
	if l.Answer == "ask" {
		note += ": a name cannot be asked about, so this allows it"
	}
	for i := range p.Entries {
		e := &p.Entries[i]
		if h, ok := e.Value.(lanPorts); ok && slices.Equal(e.Path, lanPath) && e.Key == l.Name {
			if !slices.Contains(h.Ports, l.Port) {
				h.Ports = append(slices.Clone(h.Ports), l.Port)
				slices.Sort(h.Ports)
				e.Value = h
				e.Note += "; " + note
			}
			return
		}
	}
	p.add(lanPath, l.Name, lanPorts{Ports: []int{l.Port}}, note)
	p.add(allowPath, l.Name, true, "on the local network: frisket reaches a lan name the allowlist allows")
}

// lanPorts is a frisket.lan entry: the ports a name is reached at.
type lanPorts struct {
	Ports []int `json:"ports"`
}

// syscall is a call the filter would have refused: flong's
// seccomp.syscalls, allowed. Syscalls are never asked about -- the filter
// is fixed before the session starts -- so a person's recording, and an
// ask, allow them; a recording that refused everything logs none
// (Propose).
func (p *Proposal) syscall(c Syscall, o Options) {
	calls, note := []string{"flong", "seccomp", "syscalls"}, fmt.Sprintf("logged %d time%s; loosens the tier's filter", c.Count, plural(c.Count))
	switch o.Default {
	case "ask":
		note += "; a syscall cannot be asked about, so this allows it"
	case "":
		note += "; syscalls are not put to you, but allowed and logged while recording"
	}
	if s, ok := highSurface[c.Name]; ok {
		note = "high surface, " + s + ": " + note
	}
	e := Entry{Path: calls, Key: c.Name, Value: "allow", Note: note}
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

// note is s as one line of a proposal's note: cleaned of what a terminal
// would act on, as everything chase shows is, and its line breaks spaces.
func note(s string) string {
	return strings.ReplaceAll(term.Clean(s), "\n", " ")
}

// File is the proposal as the file `chase record apply` reads,
// proposal.json, strict JSON in its canonical form: `about`, the header's
// lines; `propose`, the entries nested as chase.json nests them, which
// apply adds; `probable`, the same of entries proposed only as probable,
// which a person moves into `propose` to have them added; and `notes`,
// what each entry was made from, by a JSON pointer to it. An entry is
// proposed once; a list's entries in the order they were proposed.
func (p Proposal) File(header []string) []byte {
	about := make([]any, 0, len(header))
	for _, h := range header {
		about = append(about, note(h))
	}
	propose, probable := map[string]any{}, map[string]any{}
	notes := map[string]any{}
	for _, e := range p.Entries {
		into := propose
		if e.Off {
			into = probable
		}
		place(into, e)
		if e.Note != "" {
			n := note(e.Note)
			if was, ok := notes[e.pointer()].(string); ok && was != n {
				n = was + "; " + n
			}
			notes[e.pointer()] = n
		}
	}
	out := map[string]any{"about": about, "propose": propose, "probable": probable, "notes": notes}
	b, err := projpolicy.Encode(jsonValue(out))
	if err != nil {
		panic(err)
	}
	return b
}

// place puts e into v, a chase.json's shape: under its key, or appended to
// its list, once.
func place(v map[string]any, e Entry) {
	m := v
	path := e.Path
	if e.Key == "" {
		path = path[:len(path)-1]
	}
	for _, k := range path {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	if e.Key != "" {
		m[e.Key] = e.Value
		return
	}
	list := e.Path[len(e.Path)-1]
	items, _ := m[list].([]any)
	if !slices.Contains(items, e.Value) {
		m[list] = append(items, e.Value)
	}
}

// jsonValue is v as the JSON values projpolicy encodes: what a struct
// marshals to, decoded again.
func jsonValue(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	out, err := projpolicy.Decode(b)
	if err != nil {
		panic(err)
	}
	return out
}
