package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/danielbodart/chase/internal/term"
)

// Var is one variable added to the payload's environment.
type Var struct {
	Name  string
	Value string
}

// File is one file seeded into the payload's home: written by flong init
// inside the session, as its user, before the agent starts, following no
// link and crossing no mount, so it lands on the session's own root and goes
// with it. Written, not bound: Claude Code replaces its login and
// ~/.claude.json by renaming a new file over them, which a bind of a host
// file refuses, and which, bound as a directory, would carry back to the
// host.
type File struct {
	// Path is absolute, under Config.Home and never the home itself.
	Path string
	// Mode is the file's permission bits alone.
	Mode os.FileMode
	// Content is every byte of it, none of them a NUL.
	Content string
}

// Given is what the launch gives a session beyond what its tier does: an
// envelope's environment and files (internal/envelope's Launch).
type Given struct {
	Env   []Var
	Files []File
}

// Exec is the payload, as flong's exec prints it (Write): its whole
// argument list, the variables added to its environment, and the files
// seeded into its home.
type Exec struct {
	Argv  []string
	Env   []Var
	Files []File
}

// What Claude Code's placeholder login grants: what it offers is decided
// from the scopes it finds, so a tier with connectors is given theirs.
var (
	connectorScopes = []string{"user:file_upload", "user:inference", "user:mcp_servers", "user:profile", "user:sessions:claude_code"}
	inferenceScopes = []string{"user:inference"}
)

// launchEnv is flong's own for every session, whatever its container says
// (flong's src/spec.zig, fixed_env), and TINI_* besides, which tini, the
// session's init, reads (its init_prefix): names an exec may not set at
// all. Held here only to refuse one in chase's words; were flong to add a
// name, a launch setting it would still be refused, in flong's.
var launchEnv = []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "XDG_RUNTIME_DIR", "TMPDIR", "FLONG_BINDS", "container", "TERM", "COLORTERM", "PWD"}

// never is 2100-01-01, in milliseconds, as the placeholder login's expiry:
// it never expires, so a session never tries to refresh it, and frisket,
// which holds the real one, never refreshes anything a session holds.
const never = 4102444800000

// Payload is flong's exec for tier, run on the host after seccompPolicy: the
// payload a session of workspace runs, for the launcher's arguments args,
// the first of which names the agent. binds is flong's $binds, one PATH:ro
// or PATH:rw a line, and given what the launch's envelope adds. What it says
// to a person, it says on stderr: stdout is the payload's.
//
// The agent is one of a closed list -- claude and codex where the tier has
// them, and shell -- so a launcher's argument can never run anything else
// on the container's PATH:
//
//   - claude: Claude Code with the tier's settings, which outrank the
//     user's and the project's, its permission prompts skippable, and
//     --add-dir for every read-write bind;
//   - codex: codex, its own sandbox bypassed, since the session is the
//     sandbox, the workspace trusted by a -c override rather than in
//     config.toml, which is the host's, and --add-dir for every read-write
//     bind;
//   - shell: `bash -l`, what `chase shell` gets, the session as an agent
//     gets it with no agent. A session with Docker is told, on stderr, where
//     its containers' ports are.
//
// Its environment is the container's, which flong computes, and what the
// tier and the launch add: an isolated codex's CODEX_HOME, the Cloudflare
// account, and the envelope's exports, which win over the tier's of the
// same name, a project's own account over the tier's. flong refuses an exec
// that sets a name the container's environment already sets, or one the
// launch sets itself, and so a variable the container sets to the same
// value is left to the container, and one it sets to another value, or one
// of the launch's own, refuses the launch here, naming it: nothing is
// overridden silently. The container's is Tier.Environment, flong's own
// computation of it; a value of it that refers to the launch's HOME or USER,
// `${HOME}/x`, is never the same as the one the launch would give, and so
// refuses the launch too.
//
// Its files are Claude Code's placeholder login, an isolated tier's
// ~/.claude.json, which trusts the workspace and skips onboarding, and the
// envelope's.
func Payload(c Config, tier, workspace, binds string, args []string, given Given, stderr io.Writer) (Exec, error) {
	if err := Agent(c, tier, args); err != nil {
		return Exec{}, err
	}
	t := c.Tiers[tier]
	agent, rest := args[0], args[1:]

	var e Exec
	set := func(name, value string) {
		for i := range e.Env {
			if e.Env[i].Name == name {
				e.Env[i].Value = value
				return
			}
		}
		e.Env = append(e.Env, Var{name, value})
	}
	if cx := t.Codex; cx != nil && cx.State == "isolated" {
		// The home Binds made and bound, one per workspace.
		set("CODEX_HOME", filepath.Join(cx.StateDir, Munge(workspace)))
	}
	if cf := t.Cloudflare; cf != nil {
		b, err := os.ReadFile(cf.AccountIDFile)
		if err != nil {
			return Exec{}, fmt.Errorf("the Cloudflare account id: %w", err)
		}
		// As a command substitution took it: without its last newlines.
		set("CLOUDFLARE_ACCOUNT_ID", strings.TrimRight(string(b), "\n"))
	}
	for _, v := range given.Env {
		set(v.Name, v.Value)
	}
	env := e.Env[:0]
	for _, v := range e.Env {
		theirs, sets := t.Environment[v.Name]
		switch {
		case slices.Contains(launchEnv, v.Name) || strings.HasPrefix(v.Name, "TINI_"):
			return Exec{}, fmt.Errorf("the launch would set %s, which flong sets for every session itself", v.Name)
		case !sets:
			env = append(env, v)
		case theirs != v.Value:
			return Exec{}, fmt.Errorf("%s's container sets %s to %q, and the launch would set it to %q", tier, v.Name, theirs, v.Value)
		}
	}
	e.Env = env

	// Only :rw binds: codex's --add-dir means writable. Not ~/.claude's,
	// which are Claude Code's storage, not work.
	var dirs []string
	for _, l := range strings.Split(binds, "\n") {
		if p, rw := strings.CutSuffix(l, ":rw"); rw && !strings.HasPrefix(l, c.Home+"/.claude/") {
			dirs = append(dirs, p)
		}
	}

	switch {
	case agent == "claude" && t.Claude != nil:
		// --add-dir first, one for each directory, and never last: Claude
		// Code's --add-dir is variadic, taking every word after it up to
		// the next option, so with the directories last a launcher's
		// positional prompt -- `claude "fix the tests"` -- would be taken
		// as one more directory to add, as the script's launcher took it.
		// --settings after them ends the list whatever the launcher's
		// arguments are.
		e.Argv = []string{"claude"}
		for _, d := range dirs {
			e.Argv = append(e.Argv, "--add-dir", d)
		}
		e.Argv = append(e.Argv, "--settings", t.Claude.Settings, "--allow-dangerously-skip-permissions")
	case agent == "codex" && t.Codex != nil:
		// ignore_default_excludes is codex's own default, set here because
		// the session depends on it: the excludes it would otherwise apply
		// are *KEY*, *SECRET* and *TOKEN*, which take GH_TOKEN off every
		// command and leave gh quietly unauthenticated.
		e.Argv = []string{"codex",
			"--dangerously-bypass-approvals-and-sandbox",
			"-c", `projects."` + tomlString(workspace) + `".trust_level="trusted"`,
			"-c", "shell_environment_policy.ignore_default_excludes=true",
		}
		for _, d := range dirs {
			e.Argv = append(e.Argv, "--add-dir", d)
		}
	case agent == "shell":
		dockerBanner(e.Env, stderr)
		e.Argv = []string{"bash", "-l"}
	default:
		return Exec{}, fmt.Errorf("unknown agent '%s': %s runs %s", agent, tier, strings.Join(agents(t), ", "))
	}
	e.Argv = append(e.Argv, rest...)

	if cl := t.Claude; cl != nil {
		scopes := inferenceScopes
		if cl.Connectors {
			scopes = connectorScopes
		}
		login, err := compact(claudeLogin{ClaudeAiOauth: claudeOauth{
			AccessToken:           c.Placeholder,
			ExpiresAt:             never,
			RefreshToken:          c.Placeholder,
			RefreshTokenExpiresAt: never,
			Scopes:                scopes,
			SubscriptionType:      "max",
		}})
		if err != nil {
			return Exec{}, err
		}
		e.Files = append(e.Files, File{Path: filepath.Join(c.Home, ".claude", ".credentials.json"), Mode: 0o600, Content: login})
		if cl.State == "isolated" {
			trust, err := indented(claudeJSON{HasCompletedOnboarding: true, Projects: map[string]claudeProject{workspace: {HasTrustDialogAccepted: true}}})
			if err != nil {
				return Exec{}, err
			}
			e.Files = append(e.Files, File{Path: filepath.Join(c.Home, ".claude.json"), Mode: 0o600, Content: trust})
		}
	}
	e.Files = append(e.Files, given.Files...)

	if err := e.check(c.Home); err != nil {
		return Exec{}, err
	}
	return e, nil
}

// Agent refuses a launch whose launcher's arguments args name no agent
// tier runs, or whose tier is not a sandbox's, as Payload does: the same
// words, from the same closed list. It is Payload's first step, and is
// taken on its own before anything else the exec hook does, so a launch
// that was always going to be refused is refused before an envelope is
// applied -- before its stage is consumed, a secret decrypted, a token
// minted from Google with the real key or a unit started for it -- and not
// after, with flong's postStop left to undo it all.
func Agent(c Config, tier string, args []string) error {
	t, ok := c.Tiers[tier]
	if !ok {
		return fmt.Errorf("%s is not a sandbox tier", tier)
	}
	if len(args) == 0 {
		return fmt.Errorf("no agent named: the launcher's first argument is the agent, one of %s", strings.Join(agents(t), ", "))
	}
	if !slices.Contains(agents(t), args[0]) {
		return fmt.Errorf("unknown agent '%s': %s runs %s", args[0], tier, strings.Join(agents(t), ", "))
	}
	return nil
}

// agents is the agents tier runs, as a person would name them.
func agents(t Tier) []string {
	var out []string
	if t.Claude != nil {
		out = append(out, "claude")
	}
	if t.Codex != nil {
		out = append(out, "codex")
	}
	return append(out, "shell")
}

// dockerBanner tells a person at `chase shell` where a project's Docker
// containers' ports are, from what its launch exported: the names are the
// session's own, which frisket answers, and a port is relayed to 127.0.0.1
// too.
func dockerBanner(env []Var, stderr io.Writer) {
	get := func(name string) string {
		for _, v := range env {
			if v.Name == name {
				return v.Value
			}
		}
		return ""
	}
	address := get("CHASE_DOCKER_ADDRESS")
	if address == "" {
		return
	}
	name, _, _ := strings.Cut(get("CHASE_DOCKER_NAMES"), " ")
	if name != "" {
		name += " → "
	}
	if ports := get("CHASE_DOCKER_PORTS"); ports != "" {
		fmt.Fprintln(stderr, term.Clean("docker: "+name+address+", ports "+ports+"; localhost works too"))
	} else {
		fmt.Fprintln(stderr, term.Clean("docker: "+name+address+", no ports"))
	}
}

// tomlString is s as it may stand between a TOML basic string's quotes:
// each backslash, and then each quote, escaped, as the script's parameter
// expansions escaped the workspace. A control character is left as it is,
// and codex then refuses the override, as it did.
func tomlString(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
}

// claudeLogin is Claude Code's placeholder login, shaped like the real one,
// since Claude Code decides what to offer from it; its fields in the order
// Nix's builtins.toJSON wrote them, which is sorted.
type claudeLogin struct {
	ClaudeAiOauth claudeOauth `json:"claudeAiOauth"`
}

type claudeOauth struct {
	AccessToken           string   `json:"accessToken"`
	ExpiresAt             int64    `json:"expiresAt"`
	RefreshToken          string   `json:"refreshToken"`
	RefreshTokenExpiresAt int64    `json:"refreshTokenExpiresAt"`
	Scopes                []string `json:"scopes"`
	SubscriptionType      string   `json:"subscriptionType"`
}

// claudeJSON is an isolated tier's ~/.claude.json: onboarding done, and the
// workspace's folder-trust dialog already answered.
type claudeJSON struct {
	HasCompletedOnboarding bool                     `json:"hasCompletedOnboarding"`
	Projects               map[string]claudeProject `json:"projects"`
}

type claudeProject struct {
	HasTrustDialogAccepted bool `json:"hasTrustDialogAccepted"`
}

// compact is v's JSON on one line with nothing after it, as builtins.toJSON
// wrote the login and printf '%s' put it in the file: no character escaped
// that JSON does not require.
func compact(v any) (string, error) {
	s, err := encode(v, "")
	return strings.TrimSuffix(s, "\n"), err
}

// indented is v's JSON as `jq -n` printed it: two spaces an indent, and a
// newline at the end.
func indented(v any) (string, error) { return encode(v, "  ") }

func encode(v any, indent string) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// check refuses what flong's protocol cannot carry, or would carry as
// something else, before a byte of it is printed: a NUL anywhere, since
// every field ends at one; a variable's name that is empty or holds an '=',
// where flong splits it; a program that is empty; a mode past the
// permission bits; and a file anywhere but under home. flong refuses each
// too, and more -- a name the session already sets, a path with a `..` --
// but these are chase's own to get right, and said as chase's.
func (e Exec) check(home string) error {
	if len(e.Argv) == 0 || e.Argv[0] == "" {
		return fmt.Errorf("no program to run")
	}
	for _, a := range e.Argv {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("an argument %q has a NUL in it", a)
		}
	}
	for _, v := range e.Env {
		if v.Name == "" || strings.ContainsAny(v.Name, "=\x00") || strings.ContainsRune(v.Value, 0) {
			return fmt.Errorf("%q=%q cannot be a variable of the session's", v.Name, v.Value)
		}
	}
	for _, f := range e.Files {
		if !strings.HasPrefix(f.Path, home+"/") || f.Path != filepath.Clean(f.Path) || strings.ContainsRune(f.Path, 0) {
			return fmt.Errorf("%q is not a file in %s", f.Path, home)
		}
		if f.Mode&^0o777 != 0 {
			return fmt.Errorf("%s: mode %v is not permission bits alone", f.Path, f.Mode)
		}
		if strings.ContainsRune(f.Content, 0) {
			return fmt.Errorf("%s has a NUL in it", f.Path)
		}
	}
	return nil
}

// Write prints e as flong reads exec's output: fields each ended by a NUL,
// `env:NAME=VALUE` for each variable, `arg:WORD` for each word of the
// argument list, its program first, and `file:MODE:PATH` for each file
// followed by one field that is its content.
func (e Exec) Write(w io.Writer) error {
	var b bytes.Buffer
	field := func(s string) {
		b.WriteString(s)
		b.WriteByte(0)
	}
	for _, v := range e.Env {
		field("env:" + v.Name + "=" + v.Value)
	}
	for _, a := range e.Argv {
		field("arg:" + a)
	}
	for _, f := range e.Files {
		field(fmt.Sprintf("file:%04o:%s", uint32(f.Mode.Perm()), f.Path))
		field(f.Content)
	}
	_, err := w.Write(b.Bytes())
	return err
}
