package record_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/record"
)

// `chase record`'s own flags come before the agent, or before `--`, and
// everything after the agent is the agent's, flags too: a person's
// `chase record shell -c 'x --default y'` says nothing to chase.
func TestTheAgentsArgumentsAreItsOwn(t *testing.T) {
	for _, c := range []struct {
		args []string
		want record.Args
	}{
		{[]string{"claude"}, record.Args{Options: record.Options{Base: "tier"}, Agent: "claude", Args: []string{}}},
		{[]string{"--default", "allow", "claude", "-p", "x"}, record.Args{Options: record.Options{Default: "allow", Base: "tier"}, Agent: "claude", Args: []string{"-p", "x"}}},
		{[]string{"--default=ask", "--base=none", "--", "shell", "-c", "true"}, record.Args{Options: record.Options{Default: "ask", Base: "none"}, Agent: "shell", Args: []string{"-c", "true"}}},
		{[]string{"--default=refuse", "--", "shell"}, record.Args{Options: record.Options{Default: "refuse", Base: "tier"}, Agent: "shell", Args: []string{}}},
		{[]string{"codex", "--default", "allow"}, record.Args{Options: record.Options{Base: "tier"}, Agent: "codex", Args: []string{"--default", "allow"}}},
		{[]string{"--base", "tier", "--default", "ask", "shell"}, record.Args{Options: record.Options{Default: "ask", Base: "tier"}, Agent: "shell", Args: []string{}}},
	} {
		got, err := record.ParseArgs(c.args)
		if err != nil || got.Options != c.want.Options || got.Agent != c.want.Agent || !slices.Equal(got.Args, c.want.Args) {
			t.Errorf("%q is %+v, %v", c.args, got, err)
		}
	}
	for _, bad := range [][]string{
		{}, {"--default", "always", "claude"}, {"--default=Allow", "claude"}, {"--base", "everything", "shell"},
		{"--what", "shell"}, {"--default"}, {"--", "-p"}, {"--default", "allow"}, {""},
		// Refusing, nothing is logged, and from scratch every call refused.
		{"--default", "refuse", "--base", "none", "shell"},
	} {
		if got, err := record.ParseArgs(bad); err == nil {
			t.Errorf("%q was read as %+v", bad, got)
		}
	}
}

// One of journald's audit entries, as `journalctl -o json` gives it: a
// seccomp record of a call the filter logged.
const auditEntry = `{"_TRANSPORT":"audit","_AUDIT_TYPE":"1326","_AUDIT_TYPE_NAME":"SECCOMP","MESSAGE":"SECCOMP auid=1000 uid=1000 gid=100 ses=3 pid=12337 comm=\"strace\" exe=\"/nix/store/x-strace/bin/strace\" sig=0 arch=c000003e syscall=101 compat=0 ip=0x7a29f990c6eb code=0x7ffc0000","_AUDIT_FIELD_ARCH":"c000003e","_AUDIT_FIELD_SYSCALL":"101","_AUDIT_FIELD_CODE":"0x7ffc0000","_UID":"1000","_PID":"12337","__REALTIME_TIMESTAMP":"1790958284381050"}`

// A logged call is read from journald's fields, or from the record itself
// where they are not; anything else -- another user's, a call the filter
// refused rather than logged, another kind of record -- is not one.
func TestALoggedCallIsReadFromTheAudit(t *testing.T) {
	e, ok := record.ParseAudit([]byte(auditEntry), 1000)
	if !ok || e.PID != 12337 || e.Arch != "c000003e" || e.Syscall != 101 || !e.Time.Equal(time.UnixMicro(1790958284381050)) {
		t.Errorf("%+v, %v", e, ok)
	}
	message := `{"MESSAGE":"auid=1000 uid=1000 gid=100 ses=3 pid=7 comm=\"x\" sig=0 arch=40000003 syscall=26 compat=1 ip=0x1 code=0x7ffc0000"}`
	if e, ok := record.ParseAudit([]byte(message), 1000); !ok || e.PID != 7 || e.Arch != "40000003" || e.Syscall != 26 {
		t.Errorf("the record alone was read as %+v, %v", e, ok)
	}
	for name, entry := range map[string]string{
		"another user's":  strings.ReplaceAll(auditEntry, `"_UID":"1000"`, `"_UID":"1001"`),
		"refused":         strings.ReplaceAll(auditEntry, `"_AUDIT_FIELD_CODE":"0x7ffc0000"`, `"_AUDIT_FIELD_CODE":"0x50001"`),
		"another record":  strings.ReplaceAll(auditEntry, `"_AUDIT_TYPE":"1326"`, `"_AUDIT_TYPE":"1300"`),
		"no pid":          strings.ReplaceAll(strings.ReplaceAll(auditEntry, `"_PID":"12337",`, ""), "pid=12337 ", ""),
		"not JSON at all": "SECCOMP auid=1000",
	} {
		if e, ok := record.ParseAudit([]byte(entry), 1000); ok {
			t.Errorf("%s was read as %+v", name, e)
		}
	}
}

// A CALL IS THE SESSION'S by its process's cgroup -- under
// flong-sessions.service, the container, then the session -- or, gone
// before that was read, by a pid seen in the session's cgroup. One that
// neither places is the session's only probably, by when it was made, and
// only when no other recording ran beside it.
func TestALoggedCallIsPutDownToItsSession(t *testing.T) {
	holder := "0::/user.slice/user-1000.slice/user@1000.service/app.slice/flong-sessions.service"
	from := time.Unix(1000, 0)
	at := func(s int) time.Time { return from.Add(time.Duration(s) * time.Second) }
	events := []record.Event{
		{PID: 1, Time: at(1), Cgroup: holder + "/chase-trusted/m1/sandbox\n"},
		{PID: 2, Time: at(1), Cgroup: holder + "/chase-trusted/m2/sandbox\n"},
		{PID: 3, Time: at(1), Cgroup: "0::/user.slice/user-1000.slice/session-3.scope\n"},
		{PID: 4, Time: at(1)},
		{PID: 5, Time: at(2)},
		{PID: 6, Time: at(20)},
		// A pid seen in the session, read since in another's: the cgroup
		// read says more.
		{PID: 7, Time: at(1), Cgroup: holder + "/chase-trusted/m2/sandbox\n"},
	}
	pids := map[int]bool{4: true, 7: true}
	a := record.Attribute(events, "m1", pids, from, at(10), true)
	pidsOf := func(es []record.Event) []int {
		var out []int
		for _, e := range es {
			out = append(out, e.PID)
		}
		return out
	}
	if !slices.Equal(pidsOf(a.Sure), []int{1, 4}) || !slices.Equal(pidsOf(a.Probable), []int{5}) || a.Elsewhere != 3 || a.Unsure != 1 {
		t.Errorf("alone: %+v", a)
	}
	a = record.Attribute(events, "m1", pids, from, at(10), false)
	if len(a.Probable) != 0 || a.Unsure != 2 {
		t.Errorf("beside another recording, a call was placed by time: %+v", a)
	}
	if record.Place(holder+"/chase-trusted/m10/sandbox", "m1") != record.Elsewhere || record.Place("", "m1") != record.Gone {
		t.Error("a session's name was matched by its prefix, or a gone process placed")
	}
}

// Each call is named once, by flong's tables, and counted; one put down to
// the session surely is not probable however often it was also seen
// unplaced; one that cannot be named is said, once.
func TestLoggedCallsAreNamedAndCounted(t *testing.T) {
	names := map[int64]string{101: "ptrace", 425: "io_uring_setup"}
	asked := 0
	name := func(arch string, nr int64) (string, error) {
		asked++
		if n, ok := names[nr]; ok && arch == "c000003e" {
			return n, nil
		}
		return "", fmt.Errorf("syscall %d on arch %s: no such call", nr, arch)
	}
	e := func(nr int64) record.Event { return record.Event{Arch: "c000003e", Syscall: nr} }
	calls, unnamed := record.Summarise(record.Attributed{
		Sure:     []record.Event{e(101), e(101), e(9999), e(9999)},
		Probable: []record.Event{e(101), e(425)},
	}, name)
	want := []record.Syscall{{Name: "io_uring_setup", Count: 1, Probable: true}, {Name: "ptrace", Count: 3}}
	if !slices.Equal(calls, want) {
		t.Errorf("%+v", calls)
	}
	if len(unnamed) != 1 || !strings.Contains(unnamed[0], "9999") {
		t.Errorf("%q", unnamed)
	}
}

// flong's own resolve, where the test has it (FLONG_SECCOMP), names a
// call as the module's does.
func TestFlongNamesACall(t *testing.T) {
	bin := os.Getenv("FLONG_SECCOMP")
	if bin == "" {
		t.Skip("FLONG_SECCOMP is not set: flong's resolve is the VM test's to run")
	}
	out, err := exec.Command(bin, "resolve", "c000003e", "101").Output()
	if err != nil || strings.TrimSpace(string(out)) != "ptrace" {
		t.Errorf("%s, %v", out, err)
	}
}

// What frisket's sink holds is read back: the session's own lines, its
// last line saying it filled, and anything not frisket's counted and
// skipped. Its journal, when the sink cannot be read, is slog's JSON, a
// record line of the session's among others.
func TestFrisketsLinesAreReadBack(t *testing.T) {
	sink := strings.Join([]string{
		`{"time":"2026-10-02T21:14:03.5Z","session":"m1","policy":"trusted","kind":"http","route":"github","method":"DELETE","host":"api.github.com","path":"/repos/o/r/git/refs/heads/x","operation":"git/delete-ref","would":"refuse","rule":"path","answer":"allow","source":"default"}`,
		`{"session":"m2","kind":"dns","name":"other.example","would":"refuse","answer":"allow","source":"telemetry"}`,
		`not json`,
		`{"session":"m1"}`,
		``,
		`{"session":"m1","kind":"egress","name":"registry.npmjs.org","port":443,"address":"104.16.1.34:443","would":"refuse","rule":"not allowed","answer":"allow","source":"default"}`,
		`{"time":"2026-10-02T21:15:00Z","truncated":true,"max":67108864}`,
	}, "\n")
	lines, skipped, truncated, err := record.ReadLines(strings.NewReader(sink), "m1")
	if err != nil || len(lines) != 2 || skipped != 2 || !truncated {
		t.Fatalf("%+v %d %v %v", lines, skipped, truncated, err)
	}
	if l := lines[0]; l.Kind != "http" || l.Operation != "git/delete-ref" || l.Answer != "allow" || l.Time.IsZero() {
		t.Errorf("%+v", l)
	}
	if l := lines[1]; l.Kind != "egress" || l.Port != 443 || l.Name != "registry.npmjs.org" {
		t.Errorf("%+v", l)
	}
	journal := strings.Join([]string{
		`{"time":"2026-10-02T21:14:03Z","level":"INFO","msg":"request","session":"m1","rule":"recorded"}`,
		`{"time":"2026-10-02T21:14:03Z","level":"INFO","msg":"record","session":"m1","policy":"trusted","kind":"ssh","route":"server","command":"systemctl restart nginx","would":"ask","answer":"ask","source":"human"}`,
		`{"time":"2026-10-02T21:14:03Z","level":"INFO","msg":"record","session":"m2","kind":"dns","name":"x"}`,
	}, "\n")
	j := record.ReadJournal(strings.NewReader(journal), "m1")
	if len(j) != 1 || j[0].Command != "systemctl restart nginx" || j[0].Source != "human" {
		t.Errorf("%+v", j)
	}
}

func line(kind string, set func(*record.Line)) record.Line {
	l := record.Line{Kind: kind, Would: "refuse", Answer: "allow", Source: "default"}
	set(&l)
	return l
}

// A RECORDING'S LINES, PROPOSED: each answered subject an entry in the
// list its answer says, exactly what was seen; what no grant can hold left
// out and said why; a call the grant or, from scratch, the tier allows
// already, not proposed again.
func TestWhatWasAnsweredIsProposed(t *testing.T) {
	lines := []record.Line{
		line("http", func(l *record.Line) {
			l.Route, l.Method, l.Host, l.Path, l.Operation, l.Rule = "github", "DELETE", "api.github.com", "/repos/o/r/git/refs/heads/x", "git/delete-ref", "path"
		}),
		line("http", func(l *record.Line) {
			l.Route, l.Method, l.Host, l.Path, l.Would, l.Rule, l.Answer, l.Source = "github", "POST", "api.github.com", "/new/thing", "ask", "unmatched", "ask", "human"
		}),
		// Asked again, and answered otherwise: the last answer stands.
		line("http", func(l *record.Line) {
			l.Route, l.Method, l.Host, l.Path, l.Would, l.Rule, l.Answer, l.Source = "github", "POST", "api.github.com", "/new/thing", "ask", "unmatched", "refuse", "human"
		}),
		line("http", func(l *record.Line) { l.Route, l.Method, l.Path, l.GraphQL = "github", "POST", "/graphql", "mutation" }),
		line("http", func(l *record.Line) { l.Route, l.Method, l.Path = "claude", "POST", "/v1/x" }),
		line("http", func(l *record.Line) { l.Route, l.Method, l.Path = "github", "GET", "/repos/*/x" }),
		line("ssh", func(l *record.Line) {
			l.Route, l.User, l.Address, l.Command, l.Operation, l.Would, l.Rule = "server", "ops", "192.168.1.20:22", "systemctl restart nginx", "restart", "ask", "systemctl restart *"
		}),
		line("ssh", func(l *record.Line) { l.Route, l.Command, l.Answer = "server", "ls -la /srv", "ask" }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "uptime" }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "rm -rf *" }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "box", "show version" }),
		line("egress", func(l *record.Line) { l.Name, l.Port, l.Rule = "registry.npmjs.org", 443, "not allowed" }),
		line("egress", func(l *record.Line) {
			l.Name, l.Port, l.Answer, l.Source = "nas.lan", 445, "ask", "human"
			l.LAN = true
		}),
		// The same name at another port, answered by the default: one
		// entry, with both ports.
		line("egress", func(l *record.Line) {
			l.Name, l.Port = "nas.lan", 139
			l.LAN = true
		}),
		line("egress", func(l *record.Line) {
			l.Name, l.Port, l.Answer, l.Source = "printer.lan", 631, "refuse", "human"
			l.LAN = true
		}),
		// A project's name is its own loopback address, never the LAN's.
		line("egress", func(l *record.Line) {
			l.Name, l.Port = "shop.example.internal", 80
			l.LAN = true
		}),
		line("egress", func(l *record.Line) { l.Name, l.Port, l.Answer, l.Source = "intranet.example", 443, "ask", "human" }),
		line("egress", func(l *record.Line) { l.Name, l.Port, l.Answer, l.Source = "evil.example", 443, "refuse", "human" }),
		line("egress", func(l *record.Line) {
			l.Address, l.Answer, l.Source, l.Reason = "203.0.113.9:443", "refuse", "hard", "not resolved by this session"
		}),
		line("dns", func(l *record.Line) { l.Name, l.Source = "registry.npmjs.org", "telemetry" }),
		line("http", func(l *record.Line) {
			l.Route, l.Method, l.Path, l.Answer, l.Source = "github", "PUT", "/x", "refuse", "unanswered"
		}),
	}
	calls := []record.Syscall{
		{Name: "ptrace", Count: 3}, {Name: "io_uring_setup", Count: 1}, {Name: "keyctl", Count: 1, Probable: true}, {Name: "membarrier", Count: 9},
	}
	against := record.Against{Hosts: map[string]bool{"server": true}, Allowed: map[string]bool{"membarrier": true}}
	p := record.Propose(lines, calls, record.Options{Default: "allow", Base: "tier"}, against)

	type entry struct {
		path  string
		value any
		off   bool
	}
	var got []entry
	notes := map[string]string{}
	for _, e := range p.Entries {
		v, _ := json.Marshal(e.Value)
		got = append(got, entry{strings.Join(e.Path, "."), string(v), e.Off})
		notes[string(v)] = e.Note
	}
	want := []entry{
		{"apps.github.allow", `"git/delete-ref"`, false},
		{"apps.github.refuse", `{"methods":["POST"],"path":"/new/thing"}`, false},
		{"apps.ssh.hosts.server.allow", `"restart"`, false},
		{"apps.ssh.hosts.server.ask", `"ls -la /srv"`, false},
		{"network.allow", `"registry.npmjs.org"`, false},
		{"network.lan", `{"name":"nas.lan","ports":[139,445]}`, false},
		{"network.allow", `"intranet.example"`, false},
		{"seccomp.allow", `"ptrace"`, false},
		{"seccomp.allow", `"io_uring_setup"`, false},
		{"seccomp.allow", `"keyctl"`, true},
	}
	if !slices.Equal(got, want) {
		t.Errorf("proposed\n%v\nnot\n%v", got, want)
	}
	for v, needle := range map[string]string{
		`"git/delete-ref"`:                     "loosens: the tier would refuse (path)",
		`"restart"`:                            "loosens: the tier would ask (systemctl restart *)",
		`"intranet.example"`:                   "a name cannot be asked about",
		`{"name":"nas.lan","ports":[139,445]}`: "on the local network, port 139",
		`"io_uring_setup"`:                     "high surface, io_uring",
		`"keyctl"`:                             "probable",
	} {
		if !strings.Contains(notes[v], needle) {
			t.Errorf("%s's note is %q, without %q", v, notes[v], needle)
		}
	}
	if strings.Contains(notes[`{"methods":["POST"],"path":"/new/thing"}`], "loosens") {
		t.Error("a refusal was said to loosen")
	}
	var left []string
	for _, l := range p.Left {
		left = append(left, l.Line.Kind+" "+l.Line.Path+l.Line.Command+l.Line.Name+": "+l.Why)
	}
	for _, needle := range []string{
		"http /graphql: a GraphQL request",
		"http /v1/x: a grant has no lists for the claude route",
		"http /repos/*/x: its path is not one a grant can name exactly",
		"ssh uptime: a one-word command",
		"ssh rm -rf *: a command with a *",
		"ssh show version: box is not a machine the grant names",
		"egress evil.example: a name off the allowlist is refused already",
		"egress printer.lan: a name off the allowlist is refused already",
		"egress shop.example.internal: network.lan: \"shop.example.internal\" is a project's name",
	} {
		if !slices.ContainsFunc(left, func(s string) bool { return strings.HasPrefix(s, needle) }) {
			t.Errorf("%q was not left out: %q", needle, left)
		}
	}
	if len(left) != 9 {
		t.Errorf("left out %q", left)
	}

	// A recording that refused everything proposes refusals, and no
	// syscall: its filter was the tier's, and logged none.
	p = record.Propose(lines[:1], calls, record.Options{Default: "refuse", Base: "tier"}, against)
	if len(p.Entries) != 1 || strings.Join(p.Entries[0].Path, ".") != "apps.github.allow" {
		t.Errorf("%+v", p.Entries)
	}
}

// What would not be the entry that was seen is not proposed: a command
// frisket cut short, which no pattern of it matches; and what may carry a
// secret, since a grant is committed with its checkout -- left out, said
// why without the secret, and with no note in any entry that repeats it.
func TestWhatCannotBeNamedExactlyOrSafelyIsLeftOut(t *testing.T) {
	long := "echo " + strings.Repeat("x", 4096) + "..."
	lines := []record.Line{
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", long }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "echo fine..." }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "mysql --password=hunter2 -e show" }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "env DB_TOKEN=abc deploy" }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", `curl -H "Authorization: Bearer x" localhost` }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "git clone https://me:pw@git.example/r" }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "deploy ghp_0123456789abcdefABCDEF0123" }),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "unlock aZ3kP9qX2mR7tL5wB8nV1c" }),
		line("ssh", func(l *record.Line) {
			l.Route, l.Command, l.Operation = "server", "restart --token=s3cr3t", "restart"
		}),
		// Neither a digest nor a path's words are a token.
		line("ssh", func(l *record.Line) {
			l.Route, l.Command = "server", "git show 9fceb02d0ae598e95dc970b74767f19372d61af8"
		}),
		line("ssh", func(l *record.Line) { l.Route, l.Command = "server", "kubectl get secrets" }),
		line("http", func(l *record.Line) { l.Route, l.Method, l.Path = "github", "GET", "/hooks/aZ3kP9qX2mR7tL5wB8nV1c/x" }),
		line("http", func(l *record.Line) {
			l.Route, l.Method, l.Path = "github", "GET", "/repos/o/r/commits/9fceb02d0ae598e95dc970b74767f19372d61af8"
		}),
	}
	p := record.Propose(lines, nil, record.Options{Default: "allow", Base: "tier"}, record.Against{Hosts: map[string]bool{"server": true}})
	var got []string
	for _, e := range p.Entries {
		v, _ := json.Marshal(e.Value)
		got = append(got, string(v))
		for _, secret := range []string{"hunter2", "s3cr3t", "aZ3kP9qX2mR7tL5wB8nV1c"} {
			if strings.Contains(e.Note, secret) {
				t.Errorf("%s's note repeats a secret: %q", v, e.Note)
			}
		}
	}
	want := []string{`"echo fine..."`, `"restart"`, `"git show 9fceb02d0ae598e95dc970b74767f19372d61af8"`, `"kubectl get secrets"`, `{"methods":["GET"],"path":"/repos/o/r/commits/9fceb02d0ae598e95dc970b74767f19372d61af8"}`}
	if !slices.Equal(got, want) {
		t.Errorf("proposed %q, not %q", got, want)
	}
	why := map[string]string{}
	for _, l := range p.Left {
		why[l.Line.Command+l.Line.Path] = l.Why
		if strings.Contains(l.Why, "hunter2") || strings.Contains(l.Why, "aZ3kP9") {
			t.Errorf("a reason repeats the secret: %q", l.Why)
		}
	}
	for command, needle := range map[string]string{
		long:                               "frisket cut the command short",
		"mysql --password=hunter2 -e show": "a flag, variable or header named for one",
		"env DB_TOKEN=abc deploy":          "a flag, variable or header named for one",
		`curl -H "Authorization: Bearer x" localhost`: "named for one",
		"git clone https://me:pw@git.example/r":       "a login in a URL",
		"deploy ghp_0123456789abcdefABCDEF0123":       "a word shaped as a token",
		"unlock aZ3kP9qX2mR7tL5wB8nV1c":               "a word shaped as a token",
		"/hooks/aZ3kP9qX2mR7tL5wB8nV1c/x":             "its path may carry a secret",
	} {
		if !strings.Contains(why[command], needle) {
			t.Errorf("%.40q was left out for %q, not %q", command, why[command], needle)
		}
	}
	if len(p.Left) != 8 {
		t.Errorf("left out %d", len(p.Left))
	}
}

// The proposal is JSONC in the grant's own shape, which a grant chase
// reads is made of; with nothing to propose, an empty object.
func TestAProposalIsAGrantsShape(t *testing.T) {
	p := record.Proposal{Entries: []record.Entry{
		{Path: []string{"apps", "github", "allow"}, Value: "git/delete-ref", Note: "DELETE api.github.com/x\x1b[2J; loosens"},
		{Path: []string{"apps", "github", "allow"}, Value: "git/delete-ref", Note: "again"},
		{Path: []string{"apps", "github", "ask"}, Value: record.Endpoint("POST", "/a&b"), Note: "POST"},
		{Path: []string{"seccomp", "allow"}, Value: "keyctl", Note: "probable", Off: true},
		{Path: []string{"network", "allow"}, Value: "registry.npmjs.org"},
	}}
	got := string(p.JSONC([]string{"chase record: m1", "line\nbreak"}))
	want := `// chase record: m1
// line break
{
  "apps": {
    "github": {
      "allow": [
        // DELETE api.github.com/x?[2J; loosens
        "git/delete-ref",
      ],
      "ask": [
        // POST
        {"methods":["POST"],"path":"/a&b"},
      ],
    },
  },
  "network": {
    "allow": [
      "registry.npmjs.org",
    ],
  },
  "seccomp": {
    "allow": [
      // probable
      // "keyctl",
    ],
  },
}
`
	if got != want {
		t.Errorf("the proposal is\n%s\nnot\n%s", got, want)
	}
	merged, _, err := record.Merge(nil, []byte(got))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grant.ParseFile(merged); err != nil {
		t.Errorf("%v: %s", err, merged)
	}
	if got := string(record.Proposal{}.JSONC([]string{"nothing"})); got != "// nothing\n{}\n" {
		t.Errorf("an empty proposal is %q", got)
	}
}

// A MERGE is an edit of the file a person keeps: its comments and layout
// stay, each entry goes where the grant has it -- after the last of its
// list, on its own line where the list is on many and inline where it is
// on one -- with the proposal's note beside it; one in its list already
// is left; one in another of the same lists is moved; and what comes out
// is a grant chase reads, or nothing.
func TestAProposalIsMergedIntoTheGrant(t *testing.T) {
	current := `{
  "secrets": "secrets.yaml",   // sops file in the checkout
  "apps": {
    // gh
    "github": { "ask": ["git/delete-ref"], "refuse": ["repos/delete"] },
    "ssh": {
      "hosts": {
        "server": {
          "address": "192.168.1.20",
          "user": "ops",
          "hostKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl server"],
        },
      },
    },
  },
  "seccomp": {
    "allow": [
      "io_uring_setup",
    ],
  },
}
`
	proposal := `// header
{
  "apps": {
    "github": {
      "allow": [
        // moved
        "git/delete-ref",
      ],
    },
    "ssh": { "hosts": { "server": { "ask": ["ls -la /srv"] } } },
  },
  "network": { "allow": ["registry.npmjs.org"] },
  "seccomp": {
    "allow": [
      // twice
      "io_uring_setup",
      // logged 3 times; loosens the tier's filter
      "ptrace",
    ],
  },
}
`
	want := `{
  "secrets": "secrets.yaml",   // sops file in the checkout
  "apps": {
    // gh
    "github": { "ask": [], "refuse": ["repos/delete"], "allow": [/* moved */ "git/delete-ref"] },
    "ssh": {
      "hosts": {
        "server": {
          "address": "192.168.1.20",
          "user": "ops",
          "hostKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl server"],
          "ask": [
            "ls -la /srv",
          ],
        },
      },
    },
  },
  "seccomp": {
    "allow": [
      "io_uring_setup",
      // logged 3 times; loosens the tier's filter
      "ptrace",
    ],
  },
  "network": {
    "allow": [
      "registry.npmjs.org",
    ],
  },
}
`
	got, changes, err := record.Merge([]byte(current), []byte(proposal))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("merged\n%s\nnot\n%s", got, want)
	}
	var said []string
	for _, c := range changes {
		said = append(said, fmt.Sprintf("%s %s %s %v", strings.Join(c.Path, "."), c.Value, c.From, c.Kept))
	}
	if !slices.Equal(said, []string{
		`apps.github.allow "git/delete-ref" ask false`,
		`apps.ssh.hosts.server.ask "ls -la /srv"  false`,
		`network.allow "registry.npmjs.org"  false`,
		`seccomp.allow "io_uring_setup"  true`,
		`seccomp.allow "ptrace"  false`,
	}) {
		t.Errorf("%q", said)
	}
	// Again, and nothing changes.
	again, changes, err := record.Merge(got, []byte(proposal))
	if err != nil || string(again) != string(got) || slices.ContainsFunc(changes, func(c record.Change) bool { return !c.Kept }) {
		t.Errorf("a second merge changed the grant: %v\n%s", err, again)
	}

	for name, bad := range map[string]string{
		"a secret":           `{"secrets": "x.yaml"}`,
		"docker":             `{"apps": {"docker": {"allow": ["x"]}}}`,
		"an app's other key": `{"apps": {"github": {"credential": {"secret": "x"}}}}`,
		"ssh's credential":   `{"apps": {"ssh": {"hosts": {"server": {"keyFile": "/x"}}}}}`,
		"not a list":         `{"network": {"allow": "x"}}`,
		"every name":         `{"network": {"allow": ["*"]}}`,
		"not an object":      `[]`,
	} {
		if out, _, err := record.Merge([]byte(current), []byte(bad)); err == nil {
			t.Errorf("%s was merged: %s", name, out)
		}
	}
	if _, _, err := record.Merge([]byte(`{"seccomp": {"allow": "x"}}`), []byte(proposal)); err == nil {
		t.Error("a grant whose list is not one was merged into")
	}
	// A machine the grant does not name is no grant's: its address, user
	// and keys are not the proposal's to give.
	if out, _, err := record.Merge(nil, []byte(`{"apps": {"ssh": {"hosts": {"box": {"allow": ["ls -la /"]}}}}}`)); err == nil {
		t.Errorf("an entry for an unnamed machine was merged: %s", out)
	}
}

// A NAME ON THE LOCAL NETWORK is in a grant's lan once: merged, a name
// already there gains the ports it lacks, in its place and with its
// comments; one there for every port is left as it is; a new one is added
// after the last.
func TestALANNameIsMergedByName(t *testing.T) {
	current := `{
  "network": {
    "lan": [
      // the NAS
      {"name": "nas.lan", "ports": [445]},
      {"name": "printer.lan"},
    ],
  },
}
`
	proposal := `{
  "network": {
    "lan": [
      // smb
      {"name": "nas.lan", "ports": [139, 445]},
      {"name": "printer.lan", "ports": [631]},
      // a camera
      {"name": "cam.lan", "ports": [554]},
    ],
  },
}
`
	want := `{
  "network": {
    "lan": [
      // the NAS
      {"name": "nas.lan", "ports": [445, 139]},
      {"name": "printer.lan"},
      // a camera
      {"name": "cam.lan", "ports": [554]},
    ],
  },
}
`
	got, changes, err := record.Merge([]byte(current), []byte(proposal))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("merged\n%s\nnot\n%s", got, want)
	}
	var said []string
	for _, c := range changes {
		said = append(said, fmt.Sprintf("%s %s %v %v", strings.Join(c.Path, "."), c.Value, c.Widened, c.Kept))
	}
	if !slices.Equal(said, []string{
		`network.lan {"name":"nas.lan","ports":[445,139]} true false`,
		`network.lan {"name":"printer.lan","ports":[631]} false true`,
		`network.lan {"name":"cam.lan","ports":[554]} false false`,
	}) {
		t.Errorf("%q", said)
	}
	again, changes, err := record.Merge(got, []byte(proposal))
	if err != nil || string(again) != string(got) || slices.ContainsFunc(changes, func(c record.Change) bool { return !c.Kept }) {
		t.Errorf("a second merge changed the grant: %v\n%s", err, again)
	}
	// What frisket would refuse in its lan, a grant refuses, so nothing
	// is merged.
	for _, bad := range []string{
		`{"network": {"lan": [{"name": "*.lan"}]}}`,
		`{"network": {"lan": [{"name": "nas.lan", "ports": [0]}]}}`,
		`{"network": {"lan": [{"name": "shop.example.internal"}]}}`,
		`{"network": {"lan": ["nas.lan"]}}`,
	} {
		if out, _, err := record.Merge(nil, []byte(bad)); err == nil {
			t.Errorf("%s was merged: %s", bad, out)
		}
	}
}

// RETENTION: the last Keep recordings stay, and any younger than KeepFor;
// one is pruned only when it is both older and further back.
func TestRecordingsArePrunedWhenOldAndMany(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for i := range 25 {
		ended := now.Add(-time.Duration(i) * 24 * time.Hour)
		m := record.Meta{Machine: fmt.Sprintf("m%02d", i), Started: ended.Add(-time.Minute), Ended: ended}
		if _, err := record.Save(dir, m, nil, []byte("{}\n")); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(dir+"/not-a-recording", 0o700)
	gone := record.Prune(dir, now, record.Keep, record.KeepFor)
	if !slices.Equal(gone, []string{"m20", "m21", "m22", "m23", "m24"}) {
		t.Errorf("pruned %q", gone)
	}
	// Younger than KeepFor, however many.
	if gone := record.Prune(dir, now, 3, record.KeepFor); !slices.Equal(gone, []string{"m14", "m15", "m16", "m17", "m18", "m19"}) {
		t.Errorf("pruned %q", gone)
	}
	if _, err := os.Stat(dir + "/not-a-recording"); err != nil {
		t.Error("a directory that is not a recording was pruned")
	}
	if fi, _ := os.Stat(dir + "/m00/record.jsonl"); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("a recording is %v", fi)
	}
}

// `chase record apply` merges a recording's proposal into its checkout's
// chase.jsonc -- the last recording's, or one named -- keeping the file's
// mode, and says what it did; a second apply adds nothing.
func TestApplyAddsTheProposalToTheCheckout(t *testing.T) {
	root := t.TempDir()
	diff, err := exec.LookPath("diff")
	if err != nil {
		t.Skip("no diff on PATH")
	}
	c := grant.Config{Home: root + "/home", State: root + "/state", Diff: diff}
	dir := record.RecordsDir(c)
	ws := root + "/ws"
	os.MkdirAll(ws, 0o755)
	os.WriteFile(ws+"/chase.jsonc", []byte("{\n  // mine\n  \"apps\": {},\n}\n"), 0o640)
	now := time.Now()
	old := record.Meta{Machine: "old", Workspace: ws, Ended: now.Add(-time.Hour)}
	record.Save(dir, old, nil, []byte(`{"network": {"allow": ["old.example"]}}`))
	last := record.Meta{Machine: "last", Workspace: ws, Ended: now}
	record.Save(dir, last, nil, []byte("{\n  \"seccomp\": {\n    \"allow\": [\n      // logged\n      \"ptrace\",\n    ],\n  },\n}\n"))

	var out, errb strings.Builder
	if rc := record.Apply(c, nil, &out, &errb); rc != 0 {
		t.Fatalf("%d: %s", rc, errb.String())
	}
	got, _ := os.ReadFile(ws + "/chase.jsonc")
	want := "{\n  // mine\n  \"apps\": {},\n  \"seccomp\": {\n    \"allow\": [\n      // logged\n      \"ptrace\",\n    ],\n  },\n}\n"
	if string(got) != want {
		t.Errorf("the grant is\n%s", got)
	}
	if fi, _ := os.Stat(ws + "/chase.jsonc"); fi.Mode().Perm() != 0o640 {
		t.Errorf("its mode is %v", fi.Mode())
	}
	if !strings.Contains(out.String(), `+      "ptrace",`) || !strings.Contains(out.String(), `"ptrace" added to seccomp.allow`) {
		t.Errorf("apply said %s", out.String())
	}
	b, _ := os.ReadFile(dir + "/last/meta.json")
	var m record.Meta
	if json.Unmarshal(b, &m) != nil || m.Applied == nil {
		t.Errorf("the recording was not marked applied: %s", b)
	}

	out.Reset()
	if rc := record.Apply(c, []string{"--last"}, &out, &errb); rc != 0 || !strings.Contains(out.String(), "nothing to add") {
		t.Errorf("a second apply: %d %s", rc, out.String())
	}
	out.Reset()
	if rc := record.Apply(c, []string{"old"}, &out, &errb); rc != 0 || !strings.Contains(out.String(), `"old.example" added to network.allow`) {
		t.Errorf("apply of a named recording: %d %s %s", rc, out.String(), errb.String())
	}
	// A chase.jsonc the session made a link or a pipe is no grant, and is
	// neither followed nor waited on.
	os.Remove(ws + "/chase.jsonc")
	os.Symlink(root+"/elsewhere", ws+"/chase.jsonc")
	os.WriteFile(root+"/elsewhere", []byte("{}"), 0o600)
	if rc := record.Apply(c, []string{"old"}, &out, &errb); rc == 0 || !strings.Contains(errb.String(), "is a link") {
		t.Errorf("apply through a link: %d %s", rc, errb.String())
	}
	if b, _ := os.ReadFile(root + "/elsewhere"); string(b) != "{}" {
		t.Errorf("apply wrote through a link: %s", b)
	}
	os.Remove(ws + "/chase.jsonc")
	if err := syscall.Mkfifo(ws+"/chase.jsonc", 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if rc := record.Apply(c, []string{"old"}, &out, &errb); rc == 0 || !strings.Contains(errb.String(), "not a plain file") {
		t.Errorf("apply of a pipe: %d %s", rc, errb.String())
	}
	for _, bad := range [][]string{{"../state"}, {"nope"}, {"a", "b"}, {".x"}} {
		errb.Reset()
		if rc := record.Apply(c, bad, &out, &errb); rc == 0 {
			t.Errorf("%q applied", bad)
		}
	}
	if rc := record.Apply(grant.Config{State: root + "/empty", Diff: diff}, nil, &out, &errb); rc == 0 {
		t.Error("apply with no recording succeeded")
	}
}

// THE REPORT says what was answered by kind, the names resolved, the
// syscalls, what no grant changes, and where the proposal is -- every byte
// of a path, command or name the session sent cleaned of what a terminal
// would act on.
func TestTheReportSaysWhatWasFound(t *testing.T) {
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	r := record.Report{
		Meta: record.Meta{Machine: "m1", Tier: "trusted", Workspace: "/w", Options: record.Options{Default: "allow", Base: "tier"}, Started: start, Ended: start.Add(12 * time.Second)},
		Lines: []record.Line{
			line("http", func(l *record.Line) {
				l.Route, l.Method, l.Host, l.Path, l.Operation, l.Rule = "github", "DELETE", "api.github.com", "/repos/o/r/git/refs/heads/x\x1b]0;pwned\x07", "git/delete-ref", "path"
			}),
			line("ssh", func(l *record.Line) {
				l.Route, l.User, l.Address, l.Command = "server", "ops", "192.168.1.20:22", "uptime"
			}),
			line("egress", func(l *record.Line) {
				l.Name, l.Port, l.Address, l.Rule = "plain.test", 80, "203.0.113.20:80", "not allowed"
			}),
			line("dns", func(l *record.Line) { l.Name, l.Source = "plain.test", "telemetry" }),
			line("egress", func(l *record.Line) {
				l.Address, l.Answer, l.Source, l.Reason = "203.0.113.9:443", "refuse", "hard", "not resolved by this session"
			}),
			line("http", func(l *record.Line) {
				l.Route, l.Method, l.Path, l.Answer, l.Source, l.Reason = "github", "PUT", "/x", "refuse", "unanswered", "no asker"
			}),
		},
		Calls:     []record.Syscall{{Name: "ptrace", Count: 2}, {Name: "keyctl", Count: 1, Probable: true}},
		Proposal:  record.Proposal{Entries: []record.Entry{{Path: []string{"seccomp", "allow"}, Value: "ptrace"}}, Left: []record.Left{{Line: record.Line{Kind: "ssh", Route: "server", Command: "uptime"}, Why: "a one-word command"}}},
		Elsewhere: 4,
		Notes:     []string{"something worth saying"},
		Dir:       "/state/records/m1",
		Diff:      "--- chase.jsonc\n+++ chase.jsonc, proposed\n",
	}
	var b strings.Builder
	r.Write(&b)
	got := b.String()
	for _, needle := range []string{
		"chase: recorded m1, trusted in /w, with --default allow and --base tier: 12s, exited 0",
		"HTTP on routes\n  allow  github  DELETE api.github.com/repos/o/r/git/refs/heads/x?]0;pwned?  git/delete-ref  would refuse: path",
		"SSH\n  allow  server  ops@192.168.1.20:22  uptime",
		"Egress\n  allow  plain.test:80  203.0.113.20:80  would refuse: not allowed",
		"DNS names resolved off the allowlist\n  plain.test",
		"Syscalls the filter would have refused\n  ptrace  2 times\n  keyctl  1 time  probable: placed by when it was made alone",
		"Refused, and no grant changes it\n  egress  203.0.113.9:443  not resolved by this session",
		"Refused for want of an answer\n  http  github PUT /x  no asker",
		"Answered, and not proposed\n  ssh  server uptime  a one-word command",
		"4 logged calls by other processes left out",
		"Proposed, in /state/records/m1/proposal.jsonc:\n--- chase.jsonc",
		"chase record apply m1",
	} {
		if !strings.Contains(got, needle) {
			t.Errorf("the report has no %q:\n%s", needle, got)
		}
	}
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("a control byte reached the terminal: %q", got)
	}

	// From scratch, every call the session made, the grant's and the
	// tier's said so.
	r.Meta.Options.Base = "none"
	r.Calls = append(r.Calls, record.Syscall{Name: "openat", Count: 9}, record.Syscall{Name: "membarrier", Count: 1})
	r.Granted = map[string]bool{"membarrier": true}
	b.Reset()
	r.Write(&b)
	if got := b.String(); !strings.Contains(got, "Syscalls the session made, but those every process makes\n  ptrace      2 times\n  keyctl      1 time   the tier's\n  openat      9 times  the tier's\n  membarrier  1 time   the grant's\n") {
		t.Errorf("from scratch, the report is\n%s", got)
	}

	// A command the session sent with a line break in it is one row's
	// field still: it adds no row or section of its own.
	r.Lines = []record.Line{line("ssh", func(l *record.Line) {
		l.Route, l.User, l.Address, l.Command = "server", "ops", "192.168.1.20:22", "true\n\nNothing to propose.\tfake"
	})}
	r.Proposal = record.Proposal{Left: []record.Left{{Line: r.Lines[0], Why: "why\nNotes"}}}
	r.Notes = []string{"a note\nNothing to propose."}
	b.Reset()
	r.Write(&b)
	if got := b.String(); strings.Contains(got, "\nNothing to propose.  ") || strings.Contains(got, "\nNotes\n  Notes") ||
		!strings.Contains(got, "true  Nothing to propose. fake") || !strings.Contains(got, "a note Nothing to propose.") {
		t.Errorf("a line break the session sent made rows of its own:\n%s", got)
	}
}

// The tokens a recording leaves its session's name by are its own: a
// directory no session sees, under the user's runtime.
func TestRecordingsAreKeptInTheUsersState(t *testing.T) {
	c := grant.Config{Home: "/home/alice", UID: 1000}
	if got := record.RecordsDir(c); got != "/home/alice/.local/state/chase/records" {
		t.Errorf("%s", got)
	}
	if got := grant.RecordTokens(c); got != "/run/user/1000/chase/.record" {
		t.Errorf("%s", got)
	}
	if err := (record.Config{Journalctl: "journalctl", Seccomp: "/x"}).Validate(); err == nil {
		t.Error("a relative journalctl was taken")
	}
	if err := (record.Config{Journalctl: "/j", Seccomp: "/s", Names: map[string]string{"t": "n"}}).Validate(); err == nil {
		t.Error("a relative names file was taken")
	}
}
