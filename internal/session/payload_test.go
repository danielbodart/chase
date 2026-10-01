package session

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// printed is exec's output read back as flong's parseExec reads it: fields
// each ended by a NUL, `env:NAME=VALUE`, `arg:WORD`, and `file:MODE:PATH`
// followed by one field of content. What does not read is the test's
// failure, as it would be the launch's.
type printed struct {
	env   []string
	argv  []string
	files []File
}

func parse(t *testing.T, out []byte) printed {
	t.Helper()
	if len(out) == 0 || out[len(out)-1] != 0 {
		t.Fatalf("the output does not end with a NUL: %q", out)
	}
	fields := strings.Split(string(out[:len(out)-1]), "\x00")
	var p printed
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasPrefix(f, "env:"):
			if !strings.Contains(f, "=") {
				t.Fatalf("an env: field with no '=': %q", f)
			}
			p.env = append(p.env, strings.TrimPrefix(f, "env:"))
		case strings.HasPrefix(f, "arg:"):
			p.argv = append(p.argv, strings.TrimPrefix(f, "arg:"))
		case strings.HasPrefix(f, "file:"):
			mode, path, ok := strings.Cut(strings.TrimPrefix(f, "file:"), ":")
			m, err := strconv.ParseUint(mode, 8, 32)
			if !ok || err != nil || len(mode) > 4 || m > 0o777 || i+1 == len(fields) {
				t.Fatalf("a file: field flong refuses: %q", f)
			}
			i++
			p.files = append(p.files, File{Path: path, Mode: os.FileMode(m), Content: fields[i]})
		default:
			t.Fatalf("an untagged field: %q", f)
		}
	}
	if len(p.argv) == 0 || p.argv[0] == "" {
		t.Fatalf("no program: %q", out)
	}
	return p
}

// fixture is a home and a Config with a tier of each kind: trusted with a
// shared Claude Code, connectors, a shared codex and a Cloudflare account;
// strict with an isolated Claude Code and codex; and bare-bones, with no
// agent but the shell.
type fixture struct {
	home, settings, account string
	c                       Config
}

func newFixture(t *testing.T) fixture {
	root := t.TempDir()
	f := fixture{home: filepath.Join(root, "home", "alice"), settings: "/nix/store/0000-claude-strict-settings.json", account: filepath.Join(root, "account-id")}
	if err := os.WriteFile(f.account, []byte("023e105f4ecef8ad9ca31a8372d0c353\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.c = Config{
		Home:        f.home,
		Runtime:     "/run/user/1000",
		Placeholder: "proxy-injected",
		Tiers: map[string]Tier{
			"trusted": {
				Claude:      &Claude{Scope: "host", Settings: "/nix/store/0000-claude-trusted-settings.json", Connectors: true},
				Codex:       &Codex{Scope: "host"},
				Cloudflare:  &Cloudflare{AccountIDFile: f.account},
				Environment: map[string]string{"CLOUDFLARE_API_TOKEN": "proxy-injected", "SSL_CERT_FILE": "/etc/frisket/ca-bundle.crt"},
			},
			"strict": {
				Claude: &Claude{Scope: "workspace", Settings: f.settings},
				Codex:  &Codex{Scope: "workspace", Placeholder: "/x"},
				Stores: map[string]Store{"codex": {Scope: "workspace", Root: filepath.Join(f.home, ".local/state/agents/codex"), Env: map[string]string{"CODEX_HOME": ""}}},
			},
			"plain": {},
		},
	}
	return f
}

// run is `chase hook exec TIER ARGS...` for workspace ws with binds: what
// it printed, read back, and what it said.
func (f fixture) run(t *testing.T, tier, ws, binds string, given Given, args ...string) (printed, string) {
	t.Helper()
	var stderr bytes.Buffer
	e, err := Payload(f.c, tier, ws, binds, args, given, &stderr)
	if err != nil {
		t.Fatalf("%s %q was refused: %v", tier, args, err)
	}
	var out bytes.Buffer
	if err := e.Write(&out); err != nil {
		t.Fatal(err)
	}
	return parse(t, out.Bytes()), stderr.String()
}

func (f fixture) refused(t *testing.T, tier, ws, binds string, given Given, args ...string) string {
	t.Helper()
	var stderr bytes.Buffer
	e, err := Payload(f.c, tier, ws, binds, args, given, &stderr)
	if err == nil {
		t.Fatalf("%s %q was not refused: %+v", tier, args, e)
	}
	return err.Error()
}

// The login each tier's Claude Code is given, byte for byte as Nix's
// builtins.toJSON wrote it and printf '%s' put it in the file.
func placeholderLogin(scopes string) string {
	return `{"claudeAiOauth":{"accessToken":"proxy-injected","expiresAt":4102444800000,"refreshToken":"proxy-injected",` +
		`"refreshTokenExpiresAt":4102444800000,"scopes":` + scopes + `,"subscriptionType":"max"}}`
}

// CLAUDE CODE: an --add-dir for every read-write bind but ~/.claude's, the
// tier's settings, its prompts skippable, and the launcher's arguments
// after, so that a positional prompt among them is never taken by --add-dir,
// which is variadic, as one more directory.
// It is given the placeholder login, with the scopes the tier's connectors
// need, the user's alone, and nothing else.
func TestClaudeIsRunWithTheTiersSettingsAndItsWritableBinds(t *testing.T) {
	f := newFixture(t)
	binds := strings.Join([]string{
		"/home/alice/Projects/api:rw",
		"/home/alice/Projects/docs:ro",
		f.home + "/.claude/projects/-w-shop:rw",
		f.home + "/.local/state/agents/codex/-w-shop:rw",
		"/home/alice/Projects/web:rw",
	}, "\n")
	p, said := f.run(t, "trusted", "/w/shop", binds, Given{}, "claude", "--resume", "a b")
	settings := []string{"--settings", "/nix/store/0000-claude-trusted-settings.json", "--allow-dangerously-skip-permissions"}
	dirs := []string{"--add-dir", "/home/alice/Projects/api", "--add-dir", f.home + "/.local/state/agents/codex/-w-shop", "--add-dir", "/home/alice/Projects/web"}
	want := slices.Concat([]string{"claude"}, dirs, settings, []string{"--resume", "a b"})
	if !slices.Equal(p.argv, want) {
		t.Errorf("argv is %q, not %q", p.argv, want)
	}
	// A positional prompt comes after an option that ends --add-dir's
	// list, never straight after a directory.
	p, _ = f.run(t, "trusted", "/w/shop", binds, Given{}, "claude", "fix the tests")
	if want := slices.Concat([]string{"claude"}, dirs, settings, []string{"fix the tests"}); !slices.Equal(p.argv, want) {
		t.Errorf("argv with a prompt is %q, not %q", p.argv, want)
	}
	if said != "" {
		t.Errorf("claude said %q", said)
	}
	if len(p.files) != 1 || p.files[0] != (File{Path: f.home + "/.claude/.credentials.json", Mode: 0o600,
		Content: placeholderLogin(`["user:file_upload","user:inference","user:mcp_servers","user:profile","user:sessions:claude_code"]`)}) {
		t.Errorf("a shared tier with connectors was given %+v", p.files)
	}

	// No writable bind, no --add-dir at all.
	p, _ = f.run(t, "trusted", "/w/shop", "/home/alice/Projects/docs:ro", Given{}, "claude")
	if want := slices.Concat([]string{"claude"}, settings); !slices.Equal(p.argv, want) {
		t.Errorf("argv with no writable bind is %q", p.argv)
	}
	p, _ = f.run(t, "trusted", "/w/shop", "", Given{}, "claude")
	if want := slices.Concat([]string{"claude"}, settings); !slices.Equal(p.argv, want) {
		t.Errorf("argv with no binds is %q", p.argv)
	}
}

// A Claude Code that is not the host's is given inference alone, and a
// ~/.claude.json of its own that has done onboarding and, where the tier
// trusts its checkouts, trusts the workspace, as `jq -n` wrote it.
func TestAWorkspacesClaudeTrustsItsWorkspaceWhereTheTierSays(t *testing.T) {
	f := newFixture(t)
	ws := `/w/it's "quoted" & <odd>`
	p, _ := f.run(t, "strict", ws, "", Given{}, "claude")
	if len(p.files) != 2 || p.files[1] != (File{Path: f.home + "/.claude.json", Mode: 0o600, Content: "{\n  \"hasCompletedOnboarding\": true\n}\n"}) {
		t.Errorf("a tier that does not trust was given %+v", p.files)
	}
	f.c.Tiers["strict"].Claude.Trust = true
	p, _ = f.run(t, "strict", ws, "", Given{}, "claude")
	if !slices.Equal(p.argv, []string{"claude", "--settings", f.settings, "--allow-dangerously-skip-permissions"}) {
		t.Errorf("argv is %q", p.argv)
	}
	want := []File{
		{Path: f.home + "/.claude/.credentials.json", Mode: 0o600, Content: placeholderLogin(`["user:inference"]`)},
		{Path: f.home + "/.claude.json", Mode: 0o600, Content: "{\n  \"hasCompletedOnboarding\": true,\n  \"projects\": {\n" +
			"    \"/w/it's \\\"quoted\\\" & <odd>\": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n"},
	}
	if !slices.Equal(p.files, want) {
		t.Errorf("the files are %+v, not %+v", p.files, want)
	}
}

// CODEX: its own sandbox bypassed, the workspace trusted by a -c override
// whose TOML string holds it escaped as the script escaped it where the
// tier trusts it, the default excludes off, and an --add-dir per writable
// bind. A workspace's
// CODEX_HOME is the store Binds made for it, which is no --add-dir; the
// host's is the host's ~/.codex, given nothing; and a session's own is
// seeded with the placeholder login.
func TestCodexIsTrustedInItsWorkspace(t *testing.T) {
	f := newFixture(t)
	ws := `/w/a "b" \c`
	home := filepath.Join(f.home, ".local/state/agents/codex", "strict", Munge(ws))
	p, _ := f.run(t, "strict", ws, "", Given{}, "codex")
	if slices.ContainsFunc(p.argv, func(a string) bool { return strings.Contains(a, "trust_level") }) {
		t.Errorf("a tier that does not trust told codex to: %q", p.argv)
	}
	f.c.Tiers["strict"].Codex.Trust = true
	p, _ = f.run(t, "strict", ws, "/x:rw\n/y:ro\n"+home+":rw\n/z:rw", Given{}, "codex", "exec", "hi")
	want := []string{"codex", "--dangerously-bypass-approvals-and-sandbox",
		"-c", `projects."/w/a \"b\" \\c".trust_level="trusted"`,
		"-c", "shell_environment_policy.ignore_default_excludes=true",
		"--add-dir", "/x", "--add-dir", "/z", "exec", "hi"}
	if !slices.Equal(p.argv, want) {
		t.Errorf("argv is %q, not %q", p.argv, want)
	}
	if !slices.Equal(p.env, []string{"CODEX_HOME=" + home}) {
		t.Errorf("a workspace's codex's environment is %q", p.env)
	}
	if slices.ContainsFunc(p.files, func(f File) bool { return strings.Contains(f.Path, ".codex") }) {
		t.Errorf("a workspace's codex was seeded %+v", p.files)
	}
	// The host's, its own ~/.codex is its home.
	p, _ = f.run(t, "trusted", ws, "", Given{}, "codex")
	if slices.ContainsFunc(p.env, func(v string) bool { return strings.HasPrefix(v, "CODEX_HOME=") }) {
		t.Errorf("the host's codex was given a home: %q", p.env)
	}
	// The session's: the placeholder, in a ~/.codex that goes with it.
	placeholder := filepath.Join(t.TempDir(), "auth-placeholder.json")
	os.WriteFile(placeholder, []byte(`{"placeholder":true}`), 0o600)
	f.c.Tiers["plain"] = Tier{Codex: &Codex{Scope: "session", Placeholder: placeholder}}
	p, _ = f.run(t, "plain", ws, "", Given{}, "codex")
	if len(p.env) != 0 || len(p.files) != 1 || p.files[0] != (File{Path: f.home + "/.codex/auth.json", Mode: 0o600, Content: `{"placeholder":true}`}) {
		t.Errorf("the session's codex was given %q and %+v", p.env, p.files)
	}
	os.Remove(placeholder)
	if got := f.refused(t, "plain", ws, "", Given{}, "codex"); !strings.HasPrefix(got, "codex's placeholder login: ") {
		t.Errorf("an unreadable placeholder: %q", got)
	}
}

// TRUST: each variable an app trusts the paths in is set to the workspace,
// unless the container sets it.
func TestATrustingAppsVariableIsTheWorkspace(t *testing.T) {
	f := newFixture(t)
	f.c.Tiers["plain"] = Tier{TrustEnv: []string{"MISE_TRUSTED_CONFIG_PATHS"}}
	p, _ := f.run(t, "plain", "/w/shop", "", Given{}, "shell")
	if !slices.Equal(p.env, []string{"MISE_TRUSTED_CONFIG_PATHS=/w/shop"}) {
		t.Errorf("the environment is %q", p.env)
	}
	f.c.Tiers["plain"] = Tier{TrustEnv: []string{"MISE_TRUSTED_CONFIG_PATHS"}, Environment: map[string]string{"MISE_TRUSTED_CONFIG_PATHS": "/x"}}
	if p, _ = f.run(t, "plain", "/w/shop", "", Given{}, "shell"); len(p.env) != 0 {
		t.Errorf("the container's was not left to it: %q", p.env)
	}
}

// STORES: each variable a store names is set to its path in the store's
// directory, unless the container sets it, which is then left to it; a
// grant's own value wins, as any of the tier's does; and two stores
// naming one variable refuse the launch.
func TestAStoresVariablesAreSetUnlessTheContainerSetsThem(t *testing.T) {
	f := newFixture(t)
	caches := Store{Scope: "tier", Root: "/c", Env: map[string]string{"XDG_CACHE_HOME": "cache", "GOPATH": "data/go", "CARGO_HOME": "data/cargo"}}
	f.c.Tiers["plain"] = Tier{Stores: map[string]Store{"caches": caches}, Environment: map[string]string{"GOPATH": "/srv/go"}}
	p, _ := f.run(t, "plain", "/w", "/c/plain/all:rw\n/x:rw", Given{Env: []Var{{"CARGO_HOME", "/w/.cargo"}}}, "shell")
	if want := []string{"CARGO_HOME=/w/.cargo", "XDG_CACHE_HOME=/c/plain/all/cache"}; !slices.Equal(p.env, want) {
		t.Errorf("the environment is %q, not %q", p.env, want)
	}
	f.c.Tiers["plain"] = Tier{Stores: map[string]Store{"caches": caches, "go": {Scope: "workspace", Root: "/g", Env: map[string]string{"GOPATH": ""}}}}
	if got := f.refused(t, "plain", "/w", "", Given{}, "shell"); got != "plain's stores caches and go both set GOPATH" {
		t.Errorf("two stores naming one variable: %q", got)
	}
}

// SHELL: `bash -l` and the launcher's arguments, in any tier, told nothing
// unless the launch has Docker.
func TestTheShellIsALoginBash(t *testing.T) {
	f := newFixture(t)
	p, said := f.run(t, "plain", "/w", "/x:rw", Given{}, "shell", "-c", "echo $HOME; exit 3")
	if !slices.Equal(p.argv, []string{"bash", "-l", "-c", "echo $HOME; exit 3"}) {
		t.Errorf("argv is %q", p.argv)
	}
	if said != "" || len(p.env) != 0 || len(p.files) != 0 {
		t.Errorf("a plain shell was given %q, %+v, and told %q", p.env, p.files, said)
	}
	p, _ = f.run(t, "plain", "/w", "", Given{}, "shell")
	if !slices.Equal(p.argv, []string{"bash", "-l"}) {
		t.Errorf("argv is %q", p.argv)
	}
}

// A CLOSED LIST: an agent the tier does not run, an agent that is not one,
// and no agent at all are refused, so no launcher's argument runs anything
// else on the container's PATH. So is a tier that is not a sandbox's.
func TestOnlyTheTiersAgentsRun(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		tier string
		args []string
		want string
	}{
		{"plain", []string{"claude"}, "unknown agent 'claude': plain runs shell"},
		{"plain", []string{"codex", "x"}, "unknown agent 'codex': plain runs shell"},
		{"strict", []string{"sh", "-c", "id"}, "unknown agent 'sh': strict runs claude, codex, shell"},
		{"strict", []string{"/bin/bash"}, "unknown agent '/bin/bash': strict runs claude, codex, shell"},
		{"strict", nil, "no agent named: the launcher's first argument is the agent, one of claude, codex, shell"},
		{"host", []string{"shell"}, "host is not a sandbox tier"},
	} {
		if got := f.refused(t, c.tier, "/w", "", Given{}, c.args...); got != c.want {
			t.Errorf("%s %q: %q, not %q", c.tier, c.args, got, c.want)
		}
		// Agent, which the hook asks before anything else, refuses it in
		// the same words.
		if err := Agent(f.c, c.tier, c.args); err == nil || err.Error() != c.want {
			t.Errorf("Agent(%s, %q): %v, not %q", c.tier, c.args, err, c.want)
		}
	}
	for _, c := range []struct {
		tier string
		args []string
	}{{"plain", []string{"shell"}}, {"strict", []string{"claude", "x"}}, {"strict", []string{"codex"}}, {"trusted", []string{"shell", "-c", "id"}}} {
		if err := Agent(f.c, c.tier, c.args); err != nil {
			t.Errorf("Agent(%s, %q): %v", c.tier, c.args, err)
		}
	}
}

// CLOUDFLARE: the account id is read on the host at each launch, without the
// newlines a command substitution took off, and given as a variable. A
// project's own account, from its grant, is the session's instead, in
// the tier's place; what else the grant gives follows, and its files
// after the tier's own.
func TestTheCloudflareAccountIsReadOnTheHostAndAProjectsWins(t *testing.T) {
	f := newFixture(t)
	p, _ := f.run(t, "trusted", "/w", "", Given{}, "shell")
	if !slices.Equal(p.env, []string{"CLOUDFLARE_ACCOUNT_ID=023e105f4ecef8ad9ca31a8372d0c353"}) {
		t.Errorf("the environment is %q", p.env)
	}
	given := Given{
		Env:   []Var{{"PROBE", "1"}, {"CLOUDFLARE_ACCOUNT_ID", "the project's"}, {"EMPTY", ""}},
		Files: []File{{Path: f.home + "/.config/chase/key.json", Mode: 0o600, Content: "{}\n"}},
	}
	p, _ = f.run(t, "trusted", "/w", "", given, "claude")
	if !slices.Equal(p.env, []string{"CLOUDFLARE_ACCOUNT_ID=the project's", "PROBE=1", "EMPTY="}) {
		t.Errorf("the environment is %q", p.env)
	}
	if len(p.files) != 2 || p.files[0].Path != f.home+"/.claude/.credentials.json" || p.files[1] != given.Files[0] {
		t.Errorf("the files are %+v", p.files)
	}

	// An account the host cannot read is no launch.
	os.Remove(f.account)
	if got := f.refused(t, "trusted", "/w", "", Given{}, "shell"); !strings.HasPrefix(got, "the Cloudflare account id: ") {
		t.Errorf("an unreadable account id: %q", got)
	}
}

// WHAT THE CONTAINER SETS IS THE CONTAINER'S. flong refuses an exec that
// sets a name the container's environment sets, so a variable the launch
// would set to what the container already has is left to the container,
// and one it would set to anything else refuses the launch, by name: a
// project's Cloudflare token placeholder in a tier that has its own, say,
// and a project that would point the session's CA elsewhere.
func TestWhatTheContainerSetsIsTheContainers(t *testing.T) {
	f := newFixture(t)
	p, _ := f.run(t, "trusted", "/w", "", Given{Env: []Var{{"CLOUDFLARE_API_TOKEN", "proxy-injected"}, {"PROBE", "1"}}}, "shell")
	if !slices.Equal(p.env, []string{"CLOUDFLARE_ACCOUNT_ID=023e105f4ecef8ad9ca31a8372d0c353", "PROBE=1"}) {
		t.Errorf("the environment is %q", p.env)
	}
	got := f.refused(t, "trusted", "/w", "", Given{Env: []Var{{"SSL_CERT_FILE", "/home/alice/ca.crt"}}}, "shell")
	if got != `trusted's container sets SSL_CERT_FILE to "/etc/frisket/ca-bundle.crt", and the launch would set it to "/home/alice/ca.crt"` {
		t.Errorf("a variable the container sets otherwise: %q", got)
	}
	// A value flong fills in at launch is never the launch's own text.
	f.c.Tiers["trusted"].Environment["XDG_DATA_DIRS"] = "${HOME}/.nix-profile/share:/run/current-system/sw/share"
	got = f.refused(t, "trusted", "/w", "", Given{Env: []Var{{"XDG_DATA_DIRS", "/home/alice/.nix-profile/share:/run/current-system/sw/share"}}}, "shell")
	if !strings.HasPrefix(got, "trusted's container sets XDG_DATA_DIRS to ") {
		t.Errorf("a variable the container sets with a reference: %q", got)
	}
	// What flong sets for every session is no launch's to set, whatever
	// the container says.
	for _, name := range []string{"HOME", "PATH", "PWD", "TERM", "TINI_SUBREAPER"} {
		got := f.refused(t, "plain", "/w", "", Given{Env: []Var{{name, "x"}}}, "shell")
		if got != "the launch would set "+name+", which flong sets for every session itself" {
			t.Errorf("%s: %q", name, got)
		}
	}
	// The same name in a tier whose container does not set it is the
	// launch's to give.
	p, _ = f.run(t, "plain", "/w", "", Given{Env: []Var{{"SSL_CERT_FILE", "/home/alice/ca.crt"}}}, "shell")
	if !slices.Equal(p.env, []string{"SSL_CERT_FILE=/home/alice/ca.crt"}) {
		t.Errorf("the environment is %q", p.env)
	}
}

// What flong's protocol cannot carry, or would carry as something else, is
// refused before anything is printed: a NUL in any field, a name flong would
// split elsewhere, and a file that is not in the home.
func TestWhatTheProtocolCannotCarryIsRefused(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		what  string
		given Given
		args  []string
		want  string
	}{
		{"a NUL in an argument", Given{}, []string{"shell", "a\x00b"}, `an argument "a\x00b" has a NUL in it`},
		{"a NUL in a value", Given{Env: []Var{{"A", "x\x00"}}}, []string{"shell"}, `"A"="x\x00" cannot be a variable of the session's`},
		{"an = in a name", Given{Env: []Var{{"A=B", "x"}}}, []string{"shell"}, `"A=B"="x" cannot be a variable of the session's`},
		{"an empty name", Given{Env: []Var{{"", "x"}}}, []string{"shell"}, `""="x" cannot be a variable of the session's`},
		{"a file outside the home", Given{Files: []File{{Path: "/etc/passwd", Mode: 0o600}}}, []string{"shell"}, `"/etc/passwd" is not a file in ` + f.home},
		{"the home itself", Given{Files: []File{{Path: f.home, Mode: 0o600}}}, []string{"shell"}, fmt.Sprintf("%q is not a file in %s", f.home, f.home)},
		{"a way out of the home", Given{Files: []File{{Path: f.home + "/../bob/x", Mode: 0o600}}}, []string{"shell"}, fmt.Sprintf("%q is not a file in %s", f.home+"/../bob/x", f.home)},
		{"a sibling of the home", Given{Files: []File{{Path: f.home + "2/x", Mode: 0o600}}}, []string{"shell"}, fmt.Sprintf("%q is not a file in %s", f.home+"2/x", f.home)},
		{"a setuid file", Given{Files: []File{{Path: f.home + "/x", Mode: 0o600 | os.ModeSetuid}}}, []string{"shell"}, f.home + "/x: mode urw------- is not permission bits alone"},
		{"a NUL in a file", Given{Files: []File{{Path: f.home + "/x", Mode: 0o600, Content: "a\x00"}}}, []string{"shell"}, f.home + "/x has a NUL in it"},
	} {
		if got := f.refused(t, "plain", "/w", "", c.given, c.args...); got != c.want {
			t.Errorf("%s: %q, not %q", c.what, got, c.want)
		}
	}
}

// The payload as flong reads it, byte for byte: every variable, then every
// word, then every file and its content, each field ended by a NUL, and an
// empty word or value as its tag alone.
func TestWriteIsFlongsProtocol(t *testing.T) {
	var out bytes.Buffer
	e := Exec{
		Argv:  []string{"bash", "-l", "", "a b"},
		Env:   []Var{{"A", "1=2"}, {"B", ""}},
		Files: []File{{Path: "/h/.x", Mode: 0o600, Content: "line\n"}, {Path: "/h/y", Mode: 0o7, Content: ""}},
	}
	if err := e.Write(&out); err != nil {
		t.Fatal(err)
	}
	want := "env:A=1=2\x00env:B=\x00arg:bash\x00arg:-l\x00arg:\x00arg:a b\x00file:0600:/h/.x\x00line\n\x00file:0007:/h/y\x00\x00"
	if out.String() != want {
		t.Errorf("wrote %q, not %q", out.String(), want)
	}
	out.Reset()
	e.Forward = "127.1.191.78"
	if err := e.Write(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "\x00\x00forward:127.1.191.78\x00") {
		t.Errorf("a forward was written as %q", out.String())
	}
}
