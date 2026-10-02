// Package ssh is SSH through frisket (docs/apps/ssh.md): the machines a
// project's grant names, each an SSH route frisket terminates. The session
// holds no key: frisket logs in to the machine with the user's own, and
// decides every command the session asks to run there by the catalogue's
// operations, answered as the tier says, and the project's own lists before
// them. frisket gives the session its ssh_config and the CA its host
// certificates are signed by, so nothing here is seeded into the session.
package ssh

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/term"
)

// Config is what apps/ssh.nix gives the app, as JSON.
type Config struct {
	// Tiers is every tier with SSH -- not bare, taking grants, with
	// apps.ssh.enable -- by name. A tier not here has none: a binding in it
	// is said, and adds nothing.
	Tiers map[string]Tier `json:"tiers"`
	// Catalogue is apps/ssh/operations.json in the store, read at launch:
	// the Linux catalogue, which decides every machine that names none of
	// Catalogues.
	Catalogue string `json:"catalogue"`
	// Catalogues are chase.apps.ssh.catalogues, each in the store, by the
	// name a tier's machine's catalogue names it by: a device's own
	// commands, in place of Linux's. A grant's machine names none.
	Catalogues map[string]string `json:"catalogues,omitempty"`
	// Agent is chase.apps.ssh.agentSocket and KeyFile chase.apps.ssh.keyFile,
	// what frisket logs in to every machine with: exactly one, which the
	// module asserts. Identity is the one key of the agent's to offer.
	Agent    string `json:"agent,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	Identity string `json:"identity,omitempty"`
}

// Tier is how a tier answers the catalogue's operations -- ops.answers of
// its apps.ssh, "allow", "ask" or "refuse" each (PLAN.md, decision 18).
// answers, not settings: ssh has no `authenticated`, since the grant that
// names its machines is the gate, not a credential of the tier's.
type Tier struct {
	Writes    string `json:"writes"`
	Guarded   string `json:"guarded"`
	Unmatched string `json:"unmatched"`
	// Env is apps.ssh.env: the variables a command may set for itself in
	// front of it -- `LANG=C ls`, `env TZ=UTC date` -- which frisket takes
	// off and decides the command after them as it would without. The
	// tier's, never a grant's: a name that changes what a program runs or
	// reads would make every rule a project is approved for say less than
	// it seems to, and only the machine's owner can weigh that.
	Env []string `json:"env,omitempty"`
	// Hosts are the tier's own machines, by the name ssh knows each by in
	// the sandbox: in every session of the tier, whatever its checkout's
	// grant says, each logging in with its own credential or the machine's.
	// A grant's machines are added to them, and never one of the same name
	// or address.
	Hosts map[string]TierHost `json:"hosts,omitempty"`
}

// LoadConfig reads a Config strictly, as frisket reads a policy.
func LoadConfig(b []byte) (Config, error) {
	var c Config
	if err := policy.Decode(b, &c); err != nil {
		return Config{}, fmt.Errorf("ssh config: %w", err)
	}
	return c, nil
}

// App is the SSH app. Its Prepare says to Stderr, through term, the one
// thing it says without refusing: that a tier has no SSH.
type App struct {
	Config Config
	Stderr io.Writer
}

var _ apps.App = (*App)(nil)

// Prepare is an SSH route for each machine the binding names. A refusal is
// an error whose text is "<workspace>: ssh: <why>", as Docker's is.
func (a *App) Prepare(_ context.Context, r apps.Request) (apps.Patch, error) {
	ws := r.Workspace
	die := func(format string, args ...any) (apps.Patch, error) {
		return apps.Patch{}, fmt.Errorf("%s: ssh: %s", ws, fmt.Sprintf(format, args...))
	}
	if _, ok := a.Config.Tiers[r.Tier]; !ok {
		term.Say(a.stderr(), "%s: ssh ignored: %s has no ssh", ws, r.Tier)
		return apps.Patch{}, nil
	}
	// The grant was checked when it was approved; again here, since every
	// route is made from it and a launch reads what was staged -- under a
	// catalogue that may have changed since.
	var b Binding
	if err := policy.Decode(r.Binding, &b); err != nil {
		return die("%v", err)
	}
	if len(b.Hosts) > 0 && (a.Config.Agent == "") == (a.Config.KeyFile == "") {
		return die("the machine has %s, and frisket logs in with exactly one of chase.apps.ssh.agentSocket and keyFile", credentialsSaid(a.Config))
	}
	routes, err := a.Config.routes(r.Tier, b)
	if err != nil {
		return die("%v", err)
	}
	for i := range routes {
		routes[i].Agent, routes[i].KeyFile, routes[i].Identity = a.Config.Agent, a.Config.KeyFile, a.Config.Identity
	}
	return apps.Patch{SSH: routes}, nil
}

// CheckBinding is what Prepare would refuse of a grant's SSH in a tier,
// but for the machine's credential: an id or category the catalogue does
// not have, a pattern the catalogue or the project's own lists overrule,
// a route frisket would not load. Asked when the grant is approved, so
// that a person is never asked to approve what no launch will run. A tier
// with no SSH has nothing to refuse: its launches say so, and add nothing.
func (c Config) CheckBinding(tier string, b Binding) error {
	if _, ok := c.Tiers[tier]; !ok {
		return nil
	}
	_, err := c.routes(tier, b)
	return err
}

// routes are the binding's machines in name order, each an SSH route but
// for the credential it logs in with, which is the machine's. None is one
// of the tier's own.
func (c Config) routes(name string, b Binding) ([]policy.SSHRoute, error) {
	routes, err := c.hostRoutes(name, "apps.ssh", b.Hosts, nil)
	if err != nil {
		return nil, err
	}
	if err := c.Tiers[name].clashes(b); err != nil {
		return nil, err
	}
	return routes, nil
}

// hostRoutes are hosts, which at names, in name order, each an SSH route
// decided as tier name says but for the credential it logs in with: a
// grant's machines and the tier's own alike. catalogues are the names of
// the catalogues the tier's own machines are decided by, by host; a
// grant's have none, and are decided by the Linux catalogue.
func (c Config) hostRoutes(name, at string, hosts map[string]Host, catalogues map[string]string) ([]policy.SSHRoute, error) {
	tier := c.Tiers[name]
	for _, s := range []struct{ field, answer string }{{"writes", tier.Writes}, {"guarded", tier.Guarded}, {"unmatched", tier.Unmatched}} {
		if !slices.Contains(answers, s.answer) {
			return nil, fmt.Errorf("%s's %s is %q, not one of allow, ask, refuse", name, s.field, s.answer)
		}
	}
	// frisket's own reading of the names, said of the tier that lists them
	// rather than of every machine that inherits them.
	if _, err := execrule.Compile(policy.SSHRoute{Env: tier.Env}); err != nil {
		return nil, fmt.Errorf("%s's %v", name, err)
	}
	if err := (Binding{Hosts: hosts}).Check(at); err != nil {
		return nil, err
	}
	loaded := map[string][]Operation{}
	var routes []policy.SSHRoute
	for _, host := range slices.Sorted(maps.Keys(hosts)) {
		h := hosts[host]
		named := catalogues[host]
		if named != "" && !idPattern.MatchString(named) {
			return nil, fmt.Errorf("%s.hosts.%s.catalogue: %q is not a catalogue's name, as chase.apps.ssh.catalogues has it: kebab-case, never a path", at, host, named)
		}
		ops, err := c.catalogue(named, loaded)
		if err != nil {
			return nil, fmt.Errorf("%s.hosts.%s.catalogue: %v", at, host, err)
		}
		exec, unmatched, err := rules(ops, tier, h)
		if err != nil {
			return nil, fmt.Errorf("%s.hosts.%s: %v", at, host, err)
		}
		r := policy.SSHRoute{
			Name:      host,
			Address:   h.Address,
			User:      h.User,
			HostKeys:  h.HostKeys,
			Shell:     h.Shell,
			Exec:      exec,
			Unmatched: unmatched,
		}
		// A device's shell is no shell frisket knows the grammar of, so
		// nothing is taken off the front of a command typed into it, and a
		// name to take off is refused there.
		if !h.Shell {
			r.Env = slices.Clone(tier.Env)
		}
		// Whatever else frisket refuses to load of how a route decides,
		// refused here, where the machine is named, rather than by a
		// session that does not start.
		if _, err := execrule.Compile(r); err != nil {
			return nil, fmt.Errorf("%s.hosts.%s: %v", at, host, err)
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// catalogue is the operations a machine is decided by: Linux's where it
// names no catalogue, or else the one of the machine's Catalogues it names,
// whose rules are the only ones there -- its secrets too, since the Linux
// catalogue's paths are no device's. Each is read and checked once for
// all the machines that name it, in loaded.
func (c Config) catalogue(name string, loaded map[string][]Operation) ([]Operation, error) {
	path, categories := c.Catalogue, linuxCategories
	if name != "" {
		p, ok := c.Catalogues[name]
		if !ok {
			offered := "none"
			if len(c.Catalogues) > 0 {
				offered = strings.Join(slices.Sorted(maps.Keys(c.Catalogues)), ", ")
			}
			return nil, fmt.Errorf("%q is no catalogue chase.apps.ssh.catalogues offers: it offers %s", name, offered)
		}
		path, categories = p, nil
	}
	if ops, ok := loaded[name]; ok {
		return ops, nil
	}
	ops, err := LoadCatalogue(path, categories)
	if err != nil {
		return nil, err
	}
	loaded[name] = ops
	return ops, nil
}

func credentialsSaid(c Config) string {
	if c.Agent == "" {
		return "neither"
	}
	return "both"
}

// rules are a machine's exec rules and its frisket unmatched: the
// catalogue's, each answered by what the project's lists say of its id,
// then of its category -- which allows no guarded operation -- then by its
// class as the tier says; the project's
// own patterns, each in place of a catalogue rule of the same pattern, and
// none that a stricter catalogue pattern as literal would overrule; and,
// where unmatched is "allow", a rule for every readable command that any
// more literal one comes before -- frisket's unmatched is only "ask" or
// "refuse", and what it cannot read is then refused, as an HTTP route's
// unmatched "allow" refuses what no rule could match (lib/operations.nix).
//
// An arg operation only tightens, so it is a rule only where it is
// answered "ask" or "refuse": one the project allows, or a tier answers
// "allow", is simply not there.
func rules(ops []Operation, tier Tier, h Host) ([]policy.ExecRule, string, error) {
	names := map[string]string{}
	var patterns []struct{ pattern, answer string }
	for _, l := range []struct {
		answer string
		names  []string
	}{{"allow", h.Allow}, {"ask", h.Ask}, {"refuse", h.Refuse}} {
		for _, n := range l.names {
			if kindOf(n) == patternEntry {
				patterns = append(patterns, struct{ pattern, answer string }{n, l.answer})
			} else {
				names[n] = l.answer
			}
		}
	}
	known := map[string]bool{}
	for _, o := range ops {
		known[o.ID] = true
		known["category:"+o.Category] = true
	}
	for _, n := range slices.Sorted(maps.Keys(names)) {
		if !known[n] {
			if kindOf(n) == categoryEntry {
				return nil, "", fmt.Errorf("%s is no category of the catalogue's", n)
			}
			return nil, "", fmt.Errorf("%q is no operation of the catalogue's; a command pattern has a space or a *, as %q does", n, n+" **")
		}
	}

	// A category allowed allows none of its guarded operations, so one that
	// has nothing else would be an allow that allows nothing.
	for _, n := range slices.Sorted(maps.Keys(names)) {
		if kindOf(n) != categoryEntry || names[n] != "allow" {
			continue
		}
		if !slices.ContainsFunc(ops, func(o Operation) bool { return "category:"+o.Category == n && o.Class != "guarded" }) {
			return nil, "", fmt.Errorf("allow %s allows nothing: every operation of it is guarded, which only its id allows", n)
		}
	}

	m := matcher{}
	var exec []policy.ExecRule
	for _, o := range ops {
		answer, ok := names[o.ID]
		if !ok {
			answer, ok = names["category:"+o.Category]
			// A category is a topic, not a danger: allowing it allows its
			// reads and writes, never what it guards -- find -exec is
			// search's, less + read's, apt -o packages' -- which only its
			// id allows. Asking or refusing a category holds for all of it.
			if ok && answer == "allow" && o.Class == "guarded" {
				ok = false
			}
		}
		if !ok {
			answer = map[string]string{"read": "allow", "write": tier.Writes, "guarded": tier.Guarded}[o.Class]
		}
		op := &policy.Operation{ID: o.ID, Summary: o.Summary, Description: o.Description, Class: o.Class, Category: o.Category}
		if len(o.Args) == 0 {
			for _, p := range o.Commands {
				exec = append(exec, answered(policy.ExecRule{Command: p, Operation: op}, answer))
			}
			continue
		}
		if answer == "allow" {
			continue
		}
		for _, g := range o.Args {
			if len(o.Commands) == 0 {
				exec = append(exec, answered(policy.ExecRule{Arg: g, Operation: op}, answer))
			}
			for _, p := range o.Commands {
				exec = append(exec, answered(policy.ExecRule{Command: p, Arg: g, Operation: op}, answer))
			}
		}
	}

	unmatched := h.Unmatched
	if unmatched == "" {
		unmatched = tier.Unmatched
	}
	if unmatched == "allow" {
		patterns = append([]struct{ pattern, answer string }{{"**", "allow"}}, patterns...)
	}
	// replaced is the catalogue's rules a project pattern has taken the
	// place of, which answer as the project says and not as the catalogue
	// does.
	replaced := map[int]bool{}
	for _, p := range patterns {
		at := slices.IndexFunc(exec, func(e policy.ExecRule) bool { return e.Arg == "" && e.Command == p.pattern })
		if at < 0 {
			exec = append(exec, answered(policy.ExecRule{Command: p.pattern}, p.answer))
			continue
		}
		// The project's answer, and the catalogue's operation still: it
		// says what the command is, which the project's list does not.
		exec[at] = answered(exec[at], p.answer)
		replaced[at] = true
	}
	// frisket decides a command by its most literal matching pattern, and
	// between patterns as literal as each other by the stricter: a project
	// pattern that a stricter catalogue pattern ties, over some command both
	// match, would never decide anything, and a person approving it would
	// think it did.
	for _, p := range patterns {
		for at, e := range exec {
			if e.Arg != "" || e.Operation == nil || e.Command == p.pattern ||
				literalWords(e.Command) != literalWords(p.pattern) || !m.overlap(e.Command, p.pattern) ||
				answerRank(answerOf(e)) <= answerRank(p.answer) {
				continue
			}
			// Two of the project's own patterns at odds: no id of the
			// catalogue's would settle it, since the stricter pattern
			// replaces that operation's answer again.
			if replaced[at] {
				return nil, "", fmt.Errorf("%s %q is as literal as the project's own %s %q, which is stricter, and so decides every command both match: drop one, or make the %s more literal", p.answer, p.pattern, answerOf(e), e.Command, p.answer)
			}
			return nil, "", fmt.Errorf("%s %q is as literal as the catalogue's %q (%s), which is stricter, and so decides every command both match: %s %s, or a more literal pattern", p.answer, p.pattern, e.Command, e.Operation.ID, p.answer, e.Operation.ID)
		}
	}
	// An arg rule decides after every command rule, and only ever more
	// strictly: a project pattern with a word an arg operation stricter than
	// it catches, on a command that operation's pattern covers, would decide
	// nothing that operation does not overrule. Only the operation's id
	// lifts it.
	for _, p := range patterns {
		for _, e := range exec {
			if e.Arg == "" || e.Operation == nil || e.Command != "" && !m.covers(e.Command, p.pattern) ||
				!m.literalArgMatches(e.Arg, p.pattern) || answerRank(answerOf(e)) <= answerRank(p.answer) {
				continue
			}
			return nil, "", fmt.Errorf("%s %q has an argument the catalogue's %s (%s) always makes %s, which a pattern never lifts: %s %s", p.answer, p.pattern, e.Operation.ID, e.Arg, answerOf(e), p.answer, e.Operation.ID)
		}
	}

	frisket := "refuse"
	if unmatched == "ask" {
		frisket = "ask"
	}
	// What frisket refuses to load, said here, where the grant is named.
	if frisket == "refuse" && !slices.ContainsFunc(exec, func(e policy.ExecRule) bool { return e.Arg == "" && !e.Refuse }) {
		return nil, "", fmt.Errorf("every command is refused: no rule allows or asks, and unmatched is %q", unmatched)
	}
	return exec, frisket, nil
}

// literalWords is how many of a pattern's words are neither * nor **,
// which is how literal frisket takes it to be.
func literalWords(pattern string) int {
	n := 0
	for w := range strings.SplitSeq(pattern, " ") {
		if w != "*" && w != "**" {
			n++
		}
	}
	return n
}

// matcher holds two patterns, or a glob and a pattern, to each other by
// frisket's own reading of a command (its execrule): each question is put
// as a command made to test it, which frisket decides with a rule of the
// one pattern or glob alone. What is checked here is then what frisket
// does, and not a copy of it that could drift. Each rule is compiled once.
type matcher map[policy.ExecRule]*execrule.Rules

// decides is what frisket answers command with the one rule e, and
// unmatched "ask". A rule frisket would not load matches nothing, and asks:
// no pattern or glob here is one, each being checked before it is matched.
func (m matcher) decides(e policy.ExecRule, command string) execrule.Outcome {
	r, ok := m[e]
	if !ok {
		r, _ = execrule.Compile(policy.SSHRoute{Exec: []policy.ExecRule{e}, Unmatched: "ask"})
		m[e] = r
	}
	if r == nil {
		return execrule.Ask
	}
	return r.Decide(command).Outcome
}

// matches is whether frisket matches words, a command, by pattern: one
// with no words is no command at all, which every pattern matches as
// vacuously as frisket, which never reads one.
func (m matcher) matches(pattern string, words []string) bool {
	return len(words) == 0 || m.decides(policy.ExecRule{Command: pattern, Refuse: true}, strings.Join(words, " ")) == execrule.Refuse
}

// split is a pattern's words, less a ** at the end, and whether it had one.
func split(p string) ([]string, bool) {
	ws := strings.Split(p, " ")
	if ws[len(ws)-1] == "**" {
		return ws[:len(ws)-1], true
	}
	return ws, false
}

// filler is a word none of the patterns have, standing in a test command
// for a word a * matches: a literal there is a match a * did not make.
func filler(patterns ...string) string {
	for i := 0; ; i++ {
		w := fmt.Sprintf("w%d", i)
		if !slices.ContainsFunc(patterns, func(p string) bool { return slices.Contains(strings.Split(p, " "), w) }) {
			return w
		}
	}
}

// overlap is whether some command matches both patterns. If one does, so
// does the one made of each place's literal, either pattern's, or a filler
// where both have a *, as long as the longer -- the shorter must end ** to
// match it, which frisket says.
func (m matcher) overlap(a, b string) bool {
	wa, _ := split(a)
	wb, _ := split(b)
	f := filler(a, b)
	words := make([]string, max(len(wa), len(wb)))
	for i := range words {
		switch {
		case i < len(wa) && wa[i] != "*":
			words[i] = wa[i]
		case i < len(wb) && wb[i] != "*":
			words[i] = wb[i]
		default:
			words[i] = f
		}
	}
	return m.matches(a, words) && m.matches(b, words)
}

// covers is whether every command that matches specific matches general.
// It is enough that general matches specific with a filler for each *, and,
// where specific ends **, that again with a filler more than general has
// words: a filler is matched only by a *, and the longer only by a **.
func (m matcher) covers(general, specific string) bool {
	ws, tail := split(specific)
	wg, _ := split(general)
	f := filler(general, specific)
	words := make([]string, len(ws))
	for i, w := range ws {
		words[i] = w
		if w == "*" {
			words[i] = f
		}
	}
	if !m.matches(general, words) {
		return false
	}
	if !tail {
		return true
	}
	for len(words) <= max(len(ws), len(wg)) {
		words = append(words, f)
	}
	return m.matches(general, words)
}

// literalArgMatches is whether frisket's arg rule of glob matches one of a
// pattern's literal arguments, and so every command the pattern does.
func (m matcher) literalArgMatches(glob, pattern string) bool {
	f := filler(pattern)
	for _, w := range strings.Split(pattern, " ")[1:] {
		if w != "*" && w != "**" && m.decides(policy.ExecRule{Arg: glob, Refuse: true}, f+" "+w) == execrule.Refuse {
			return true
		}
	}
	return false
}

// answerRank orders answers: allow, then ask, then refuse.
func answerRank(answer string) int { return slices.Index(answers, answer) }

// answerOf is what a rule answers.
func answerOf(r policy.ExecRule) string {
	switch {
	case r.Refuse:
		return "refuse"
	case r.Ask:
		return "ask"
	}
	return "allow"
}

// answered is r answered "allow", "ask" or "refuse".
func answered(r policy.ExecRule, answer string) policy.ExecRule {
	r.Ask, r.Refuse = answer == "ask", answer == "refuse"
	return r
}

// Stop has nothing to release: Prepare starts nothing.
func (a *App) Stop(context.Context, string) error { return nil }

func (a *App) stderr() io.Writer {
	if a.Stderr == nil {
		return io.Discard
	}
	return a.Stderr
}
