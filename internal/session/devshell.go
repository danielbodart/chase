package session

import (
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DevShell is a devShell's environment, as nix print-dev-env gives it
// (internal/devshell): what of it a session is given, and what its
// shellHook needs to run.
type DevShell struct {
	// Env is its exported variables, but nix's own, PATH's kind and those
	// an agent or bash is steered by.
	Env []Var
	// Path is its PATH, entry by entry.
	Path []string
	// DataDirs is its XDG_DATA_DIRS, prepended as nix develop does.
	DataDirs []string
	// Declarations are its other variables, arrays and functions, each a
	// line of bash that declares it: the hook's alone, never the agent's.
	Declarations []string
	// Hook is its shellHook, "" for none.
	Hook string
}

// AgentNames are the variables that steer the agent rather than the
// checkout's tools -- what it loads into itself, the endpoint and the
// account it talks to, the proxy it goes through, the certificates it
// trusts -- so a devShell's are never given to it: its exact names, the
// prefixes of others, and the suffixes. LD_LIBRARY_PATH is not among them:
// devShells rely on it, and since it can as well name a libc of the
// devShell's, these keep a devShell from steering the agent by mistake,
// not one written to. The wrapper's script drops the same names when a
// shellHook sets them, from the one pattern AgentPattern makes of these.
var AgentNames = struct{ Exact, Prefixes, Suffixes []string }{
	Exact: []string{"LD_PRELOAD", "LD_AUDIT", "GCONV_PATH", "NODE_OPTIONS", "NODE_PATH",
		"NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"NO_PROXY", "no_proxy"},
	Prefixes: []string{"ANTHROPIC_", "CLAUDE_", "CODEX_", "OPENAI_", "BUN_"},
	Suffixes: []string{"_PROXY", "_proxy"},
}

// IsAgentName is whether name is one of AgentNames.
func IsAgentName(name string) bool {
	return slices.Contains(AgentNames.Exact, name) ||
		slices.ContainsFunc(AgentNames.Prefixes, func(p string) bool { return strings.HasPrefix(name, p) }) ||
		slices.ContainsFunc(AgentNames.Suffixes, func(s string) bool { return strings.HasSuffix(name, s) })
}

// AgentPattern is AgentNames as one case pattern of bash's.
func AgentPattern() string {
	var alts []string
	alts = append(alts, AgentNames.Exact...)
	for _, p := range AgentNames.Prefixes {
		alts = append(alts, p+"*")
	}
	for _, s := range AgentNames.Suffixes {
		alts = append(alts, "*"+s)
	}
	return strings.Join(alts, "|")
}

// BashNames are the variables that change what bash itself does -- what it
// sources first, how it splits and globs, where cd goes, whether it is
// POSIX's -- never a devShell's to give the wrapper's bash or the agent's,
// nor a hook's: internal/devshell drops them from a devShell's exports and
// declarations, and the wrapper's script from what a hook hands back.
var BashNames = []string{"BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE", "EXECIGNORE", "POSIXLY_CORRECT", "IFS", "PS4", "BASH_XTRACEFD"}

// VarName is a name bash takes for a variable's.
var VarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// devShellScript is the bash that stands between flong and the agent where
// a devShell is given: its PATH ordered, its shellHook run, and then the
// agent exec'd, found on the container's PATH, never the devShell's. Its
// arguments are data alone -- pathFront, the devShell's PATH and
// XDG_DATA_DIRS, each joined with ':', the names a hook may not change,
// the hook, how many declarations follow, the declarations, and then the
// agent's argument list -- so nothing the launcher is given is ever script
// text.
//
// PATH is pathFront first, in its order, wherever its entries were; then
// the devShell's; then the rest of the container's, in its order. A hook
// runs in a subshell of the script's, with its declarations and the
// functions it calls, no positional parameters, as under nix develop, its
// stdin closed and its output on stderr, which is
// the person's: stdout may be the agent's protocol. What it can do to the
// bash that runs it -- a function named as a builtin, a readonly
// variable, an IFS of its own, a cd -- dies with the subshell, which hands
// back nothing but its exported variables, as data the script reads,
// never runs: of those, the script takes the hook's changes to the
// devShell's own, and anything new, but none of the names it may not
// change -- flong's, the container's and chase's -- none that steer the
// agent (AgentNames) or bash (BashNames), and none of bash's own; what it
// unset of the rest is unset. So its functions are never the agent's, and
// PATH is ordered again, so a `PATH=$PWD/bin:$PATH` of its own stays ahead
// of the devShell's and behind pathFront. Its status is ignored; an exit
// ends the session with its status, as it ends nix develop's, and so,
// said, does anything else that leaves the subshell handing back nothing
// whole -- a hook that replaces the builtins the subshell hands back with.
var devShellScript = `__chase_front=$1 __chase_path=$2 __chase_data=$3 __chase_keep=$4 __chase_hook=$5 __chase_n=$6
builtin shift 6
__chase_decls=("${@:1:__chase_n}")
builtin shift "$__chase_n"
__chase_prog=$(builtin type -P -- "$1") || { builtin echo "chase: $1: not found" >&2; builtin exit 127; }
__chase_order() {
  builtin local __chase_p __chase_all=$__chase_front __chase_have
  [[ -n $1 ]] && __chase_all+=${__chase_all:+:}$1
  IFS=: builtin read -ra __chase_have <<<"$PATH"
  for __chase_p in "${__chase_have[@]}"; do
    [[ :$__chase_front: == *:"$__chase_p":* ]] || __chase_all+=${__chase_all:+:}$__chase_p
  done
  builtin export PATH=$__chase_all
}
__chase_order "$__chase_path"
[[ -n $__chase_data ]] && builtin export XDG_DATA_DIRS=$__chase_data${XDG_DATA_DIRS:+:}${XDG_DATA_DIRS-}
if [[ -n $__chase_hook ]]; then
  __chase_back=()
  builtin mapfile -d '' -t __chase_back < <(
    exec 3>&1 >&2 </dev/null
    builtin set --
    { for __chase_d in "${__chase_decls[@]}"; do builtin eval "$__chase_d"; done
      builtin eval "$__chase_hook"; } 3>&-
    for __chase_k in @NAMES@; do
      [[ ${!__chase_k@a} == *x* ]] && builtin printf '%s=%s\0' "$__chase_k" "${!__chase_k}"
    done >&3
    builtin printf -- '-\0' >&3
  )
  builtin wait "$!"
  __chase_status=$?
  if [[ ${#__chase_back[@]} -eq 0 || ${__chase_back[-1]} != - ]]; then
    builtin echo "chase: the devShell's shellHook ended the session, with status $__chase_status" >&2
    builtin exit "$__chase_status"
  fi
  builtin unset -v '__chase_back[-1]'
  declare -A __chase_seen=()
  for __chase_r in "${__chase_back[@]}"; do
    __chase_k=${__chase_r%%=*}
    [[ $__chase_r == *=* && $__chase_k =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    __chase_seen[$__chase_k]=1
    case $__chase_k in @AGENT@|@BASH@|BASH*|SHELLOPTS|EUID|UID|PPID|PWD|OLDPWD|SHLVL|_|__chase_*) continue;; esac
    [[ " $__chase_keep " == *" $__chase_k "* ]] && continue
    builtin export "$__chase_k=${__chase_r#*=}"
  done
  for __chase_k in @NAMES@; do
    [[ ${!__chase_k@a} == *x* && -z ${__chase_seen[$__chase_k]-} ]] || continue
    case $__chase_k in PATH|XDG_DATA_DIRS|@AGENT@|@BASH@|BASH*|SHELLOPTS|EUID|UID|PPID|PWD|OLDPWD|SHLVL|_|__chase_*) continue;; esac
    [[ " $__chase_keep " == *" $__chase_k "* ]] || builtin unset -v "$__chase_k"
  done
  __chase_order ""
fi
builtin exec -a "$1" "$__chase_prog" "${@:2}"
`

// everyName is every variable's name, as bash expands the names that
// begin with each letter: compgen, which would list them, is not in every
// bash, nor in a devShell's.
func everyName() string {
	var all []string
	for _, r := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_" {
		all = append(all, "${!"+string(r)+"@}")
	}
	return strings.Join(all, " ")
}

func init() {
	devShellScript = strings.NewReplacer("@AGENT@", AgentPattern(), "@BASH@", strings.Join(BashNames, "|"), "@NAMES@", everyName()).Replace(devShellScript)
}

// wrap is argv run inside ds's environment by devShellScript: the
// container's bash, as `chase shell` runs it, given the script and its
// data. keep are the names a shellHook may not change: flong's own, the
// container's and chase's, never PATH or XDG_DATA_DIRS, which the script
// orders itself.
func wrap(argv []string, ds *DevShell, front, keep []string) []string {
	var names []string
	for _, k := range keep {
		if VarName.MatchString(k) && k != "PATH" && k != "XDG_DATA_DIRS" {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	out := []string{"bash", "--noprofile", "--norc", "-c", devShellScript, "chase-devshell",
		strings.Join(front, ":"), strings.Join(ds.Path, ":"), strings.Join(ds.DataDirs, ":"),
		strings.Join(names, " "), ds.Hook, strconv.Itoa(len(ds.Declarations))}
	out = append(out, ds.Declarations...)
	return append(out, argv...)
}

// keepOf is every name a hook may not change: flong's, the container's,
// and chase's own.
func keepOf(t Tier, own map[string]bool) []string {
	keep := slices.Clone(launchEnv)
	keep = append(keep, slices.Collect(maps.Keys(t.Environment))...)
	return append(keep, slices.Collect(maps.Keys(own))...)
}
