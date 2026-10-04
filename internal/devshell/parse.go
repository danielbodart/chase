package devshell

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/danielbodart/chase/internal/session"
)

// devEnv is `nix print-dev-env --json`: each variable, typed, and each bash
// function, by name.
type devEnv struct {
	BashFunctions map[string]string `json:"bashFunctions"`
	Variables     map[string]struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
	} `json:"variables"`
}

var funcName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_:.-]*$`)

// ignored are the variables nix develop does not take from a devShell:
// those of its build's own, which mean nothing outside it, or would point
// a session somewhere wrong -- stdenv's SSL_CERT_FILE is /no-cert-file.crt.
var ignored = []string{
	"BASHOPTS", "HOME", "NIX_BUILD_TOP", "NIX_ENFORCE_PURITY", "NIX_LOG_FD", "NIX_REMOTE",
	"PPID", "SHELLOPTS", "SSL_CERT_FILE", "TZ", "UID", "TMP", "TMPDIR", "TEMP", "TEMPDIR",
}

// bashOwn are bash's own variables, which a declaration of would change
// the bash that runs the hook rather than give it anything.
var bashOwn = []string{"EUID", "HOSTTYPE", "IFS", "LINENO", "MACHTYPE", "OPTERR", "OPTIND", "OSTYPE",
	"PPID", "PS4", "SHELLOPTS", "UID", "FUNCNAME", "GROUPS", "DIRSTACK", "PIPESTATUS"}

// builtins are bash's builtins and keywords, as `compgen -b -k` gives them:
// a function by one of their names would replace what the wrapper's script
// runs where the hook does, so a devShell with one and a hook is refused
// rather than given.
var builtins = []string{
	".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command",
	"compgen", "complete", "compopt", "continue", "declare", "dirs", "disown", "echo",
	"enable", "eval", "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash",
	"help", "history", "jobs", "kill", "let", "local", "logout", "mapfile", "popd",
	"printf", "pushd", "pwd", "read", "readarray", "readonly", "return", "set", "shift",
	"shopt", "source", "suspend", "test", "times", "trap", "true", "type", "typeset",
	"ulimit", "umask", "unalias", "unset", "wait",
	"!", "[[", "]]", "{", "}", "case", "coproc", "do", "done", "elif", "else", "esac",
	"fi", "for", "function", "if", "in", "select", "then", "time", "until", "while",
}

// What a launch carries: each word, an argument or a variable, below the
// kernel's own limit on one, and all of them together half of the MiB
// flong takes of an exec's output, the rest of it the session's own --
// its variables, its seeded files -- and the wrapper's script.
const (
	maxWord  = 128<<10 - 1
	maxTotal = 512 << 10
)

// parse is the session's devShell from print-dev-env's JSON b: its exported
// variables, but those nix develop ignores, those that steer the wrapper's
// bash, and those that steer the agent, which are returned to be said;
// PATH and XDG_DATA_DIRS apart; and, when it has a shellHook, every other
// variable and function, as the bash that declares it, for the hook alone.
// A name bash would not take, a value with a NUL, and anything named as
// the wrapper's own are dropped; a function named as one of bash's
// builtins, where there is a hook to declare it for, refuses the devShell,
// as does one larger than a launch carries.
func parse(b []byte) (*session.DevShell, []string, error) {
	var d devEnv
	if err := json.Unmarshal(b, &d); err != nil || d.Variables == nil {
		return nil, nil, errors.New("nix printed an environment chase does not read")
	}
	ds := &session.DevShell{}
	var dropped []string
	var hidden []string
	for _, name := range slices.Sorted(maps.Keys(d.Variables)) {
		v := d.Variables[name]
		if !session.VarName.MatchString(name) || strings.HasPrefix(name, "__chase_") {
			continue
		}
		switch v.Type {
		case "exported":
			var s string
			if json.Unmarshal(v.Value, &s) != nil || strings.ContainsRune(s, 0) {
				continue
			}
			switch {
			case name == "shellHook":
				ds.Hook = s
				ds.Env = append(ds.Env, session.Var{Name: name, Value: s})
			case name == "PATH":
				ds.Path = split(s)
			case name == "XDG_DATA_DIRS":
				ds.DataDirs = split(s)
			case slices.Contains(ignored, name), slices.Contains(session.BashNames, name):
			case session.IsAgentName(name):
				dropped = append(dropped, name)
			default:
				ds.Env = append(ds.Env, session.Var{Name: name, Value: s})
			}
		default:
			hidden = append(hidden, name)
		}
	}
	if ds.Hook != "" {
		var clash []string
		for name := range d.BashFunctions {
			if slices.Contains(builtins, name) {
				clash = append(clash, name)
			}
		}
		if len(clash) > 0 {
			slices.Sort(clash)
			return nil, nil, fmt.Errorf("its functions would replace bash's own: %s", strings.Join(clash, ", "))
		}
		for _, name := range hidden {
			if strings.HasPrefix(name, "BASH") || slices.Contains(bashOwn, name) || slices.Contains(session.BashNames, name) {
				continue
			}
			if decl, ok := declaration(name, d.Variables[name].Type, d.Variables[name].Value); ok {
				ds.Declarations = append(ds.Declarations, decl)
			}
		}
		for _, name := range slices.Sorted(maps.Keys(d.BashFunctions)) {
			body := d.BashFunctions[name]
			if !funcName.MatchString(name) || strings.HasPrefix(name, "__chase_") || strings.ContainsRune(body, 0) {
				continue
			}
			ds.Declarations = append(ds.Declarations, name+" () {\n"+body+"\n}")
		}
	}
	if err := fits(ds); err != nil {
		return nil, nil, err
	}
	return ds, dropped, nil
}

// declaration is the bash that declares a variable of print-dev-env's
// type t: a plain variable, an array or an associative array, each value
// quoted.
func declaration(name, t string, raw json.RawMessage) (string, bool) {
	switch t {
	case "var":
		var s string
		if json.Unmarshal(raw, &s) != nil || strings.ContainsRune(s, 0) {
			return "", false
		}
		return "declare -- " + name + "=" + quote(s), true
	case "array":
		var a []string
		if json.Unmarshal(raw, &a) != nil {
			return "", false
		}
		var q []string
		for _, s := range a {
			if strings.ContainsRune(s, 0) {
				return "", false
			}
			q = append(q, quote(s))
		}
		return "declare -a " + name + "=(" + strings.Join(q, " ") + ")", true
	case "associative":
		var m map[string]string
		if json.Unmarshal(raw, &m) != nil {
			return "", false
		}
		var q []string
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if strings.ContainsRune(k, 0) || strings.ContainsRune(m[k], 0) {
				return "", false
			}
			q = append(q, "["+quote(k)+"]="+quote(m[k]))
		}
		return "declare -A " + name + "=(" + strings.Join(q, " ") + ")", true
	}
	return "", false
}

// quote is s as one word of bash's, single-quoted.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// split is a list variable's entries, each one, none of them empty.
func split(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ":") {
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

// fits refuses a devShell larger than a launch carries: a word over the
// kernel's limit on one, or more than maxTotal of them all.
func fits(ds *session.DevShell) error {
	total := 0
	word := func(n int) bool {
		total += n
		return n > maxWord
	}
	over := false
	for _, v := range ds.Env {
		over = word(len(v.Name)+1+len(v.Value)) || over
	}
	for _, d := range ds.Declarations {
		over = word(len(d)) || over
	}
	over = word(len(ds.Hook)) || over
	over = word(len(strings.Join(ds.Path, ":"))) || over
	over = word(len(strings.Join(ds.DataDirs, ":"))) || over
	if over || total > maxTotal {
		return fmt.Errorf("its environment is %d bytes, more than a launch carries", total)
	}
	return nil
}
