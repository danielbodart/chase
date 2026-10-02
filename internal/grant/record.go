package grant

import (
	"context"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/files"
	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// A RECORDING SESSION is one `chase record` launches (internal/record): a
// session of the checkout's own tier, through the tier's record launcher,
// flong.chase-<tier>-record, whose hooks are this file's. What its policy
// would refuse or ask about is decided by the recording -- a default, or a
// person -- and written down, so that what the session needed can become
// the checkout's grant.
//
// Only a person starts one. The record launcher is never what a wrapper
// runs, nothing a checkout says selects it, and its own guard holds it to
// the checkout's tier as the tier's launcher's does. What it is told comes
// from the environment of the person who ran it -- `chase record` sets it
// -- which no session reaches:
//
//	CHASE_RECORD_DEFAULT  allow, ask or refuse: the answer to everything,
//	                      with nobody asked; empty or unset, each is put
//	                      to a person through frisket's asker
//	CHASE_RECORD_BASE     tier: syscalls are learnt against the tier's
//	                      filter and the grant's; none: against nothing
//	                      but Hot, so every call is seen
//	CHASE_RECORD_TOKEN    32 hex digits: where approve says which session
//	                      this is, for the `chase record` waiting on it
//
// The two halves are the tier's own two hooks with something added:
// ApproveRecording is approve with flong's `log` lines after the grant's,
// and ExecRecording is exec with frisket's record block in the session's
// document.
const (
	EnvDefault = "CHASE_RECORD_DEFAULT"
	EnvBase    = "CHASE_RECORD_BASE"
	EnvToken   = "CHASE_RECORD_TOKEN"
)

// Recording is what a recording session is told, from the environment.
type Recording struct {
	// Default is frisket's record block's: "allow", "ask" or "refuse", or
	// "" to ask a person.
	Default string
	// Base is "tier" or "none".
	Base string
	// Token names the session for `chase record`, or is "".
	Token string
}

var token = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Answers are what a recording answers with, a default or a person: what
// happens now, and what is written down.
var Answers = []string{"allow", "ask", "refuse"}

// RecordingFromEnv is the recording getenv describes, or why it is not
// one: a value that is not one of its words is refused, rather than read as
// the nearest one.
func RecordingFromEnv(getenv func(string) string) (Recording, error) {
	r := Recording{Default: getenv(EnvDefault), Base: getenv(EnvBase), Token: getenv(EnvToken)}
	if r.Default != "" && !slices.Contains(Answers, r.Default) {
		return Recording{}, refuse("%s is %q, not one of %s", EnvDefault, r.Default, strings.Join(Answers, ", "))
	}
	switch r.Base {
	case "":
		r.Base = "tier"
	case "tier", "none":
	default:
		return Recording{}, refuse("%s is %q, not tier or none", EnvBase, r.Base)
	}
	if r.Token != "" && !token.MatchString(r.Token) {
		return Recording{}, refuse("%s is not 32 hex digits", EnvToken)
	}
	return r, nil
}

// Hot is what a recording from scratch (base none) allows without logging
// it: the calls nearly every process makes many times a second, which
// would otherwise be most of the audit log and push out of it the calls a
// grant is made from. Every tier allows them, so none is anything a grant
// would need to name. Written out, as flong's lines take no pattern.
var Hot = []string{
	"read", "write", "readv", "writev", "pread64", "pwrite64", "lseek", "close",
	"futex", "sched_yield", "nanosleep", "clock_nanosleep", "clock_gettime",
	"mmap", "munmap", "mprotect", "madvise", "brk",
	"rt_sigreturn", "rt_sigprocmask",
	"poll", "ppoll", "epoll_wait", "epoll_pwait", "epoll_pwait2", "epoll_ctl",
	"getpid", "gettid",
}

// learning is r with flong's lines for learning what the session calls:
// every call of @known the filter would refuse is allowed and logged
// (`log @known`), but what the grant denies, which stays denied (`nolog`):
// a project's deny is its own word, and a recording that let it through
// would propose to allow what the grant refuses. From scratch, the lines
// apply to no names but Hot and the grant's own allow (`base none`).
func (r Recording) learning(res Result) Result {
	if r.Base == "none" {
		res.Base = "none"
		res.Allow = append(slices.Clone(Hot), slices.DeleteFunc(slices.Clone(res.Allow), func(n string) bool { return slices.Contains(Hot, n) })...)
	}
	res.Log = []string{"@known"}
	res.Nolog = slices.Clone(res.Deny)
	return res
}

// ApproveRecording is a recording session's seccompPolicy: Approve, the
// grant asked about as for any launch, and its lines with what flong
// learns by; and, for a `chase record` waiting on it, this session's name,
// which seccompPolicy is the first hook to know.
func ApproveRecording(ctx context.Context, c Config, ws, machine, tier string, rec Recording, stderr io.Writer) (Result, error) {
	res, err := Approve(ctx, c, ws, machine, tier, stderr)
	if err != nil {
		return Result{}, err
	}
	if rec.Token != "" {
		if err := announce(c, rec.Token, machine); err != nil {
			return Result{}, err
		}
	}
	return rec.learning(res), nil
}

// RecordTokens is where a recording session's name is left for the `chase
// record` that started it: <runtime>/chase/.record, which no session sees.
// <token>.pid is that `chase record`'s, and <token>.machine the session's
// name, which approve writes.
func RecordTokens(c Config) string { return c.runtime() + "/chase/.record" }

// StateDir is where chase keeps what outlives a launch: what it approved,
// each checkout's own directory, and its recordings.
func StateDir(c Config) string { return c.state() }

// announce leaves machine where the `chase record` holding tok finds it.
func announce(c Config, tok, machine string) error {
	if machine == "" || strings.ContainsAny(machine, "/\n") || machine[0] == '.' {
		return refuse("%q is not a session's name", machine)
	}
	dir := RecordTokens(c)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return files.WriteAtomic(dir+"/"+tok+".machine", []byte(machine+"\n"), 0o600)
}

// recordBlock is frisket's record block, as its policy.Record has it.
// Written here rather than with frisket's own type until chase builds
// against a frisket that has one; its fields are the same.
type recordBlock struct {
	Default string `json:"default,omitempty"`
	Sink    string `json:"sink,omitempty"`
}

// recordedDocument is a session's document with a record block: the
// block at the top, where frisket's Policy has it, in place of any the
// document's own type carries.
type recordedDocument struct {
	policy.Document
	Record recordBlock `json:"record"`
}

// block is the record block of the session named machine: its default,
// and its sink, <RecordDir>/<machine>.jsonl, when the module gives frisket
// a directory for one.
func (r Recording) block(c Config, machine string) recordBlock {
	b := recordBlock{Default: r.Default}
	if c.RecordDir != "" {
		b.Sink = c.RecordDir + "/" + machine + ".jsonl"
	}
	return b
}

// RecordSink is where frisket appends the lines of the recording session
// named machine, or "" for the journal alone.
func RecordSink(c Config, machine string) string {
	return Recording{}.block(c, machine).Sink
}

// ExecRecording is a recording session's exec: Exec, with the record block
// in the session's document. Only for a tier that takes grants, whose exec
// writes the document; e is its grant's configuration.
func ExecRecording(ctx context.Context, s session.Config, e *Config, registry map[string]apps.App, rec Recording, tier, ws, machine, binds string, args []string, stdout, stderr io.Writer) int {
	if e == nil {
		term.Say(stderr, "%s takes no grant, so nothing writes a recording's document", tier)
		return 1
	}
	return execute(ctx, s, e, registry, &rec, tier, ws, machine, binds, args, stdout, stderr)
}
