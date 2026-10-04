package devshell

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/danielbodart/chase/internal/session"
	"github.com/danielbodart/chase/internal/term"
)

// inside is chase-devshell's data, every flag a word exec gave it.
type inside struct {
	checkout, kind, nixpkgs, system, mode, nix, git string
	timeout                                         int
	front, keep                                     []string
}

// Granted is the status a session ends with when the devShell its grant
// asks for cannot be evaluated: flong's own for a session that never ran.
const Granted = 125

// backoff is how long each retry of an evaluation that met a lower path
// mid-substitution waits first: a test's to shorten.
var backoff = []time.Duration{time.Second, 3 * time.Second, 9 * time.Second}

// Inside is chase-devshell: run inside a session whose store is its own,
// ahead of the agent, it evaluates the checkout's devShell there -- as the
// launcher realises one on the host for a tier whose store is the host's
// -- and execs the same bash, which orders PATH, runs the shellHook and
// execs the agent (session.Wrap). args are its flags, then "--" and the
// agent's argument list; environ is the session's environment.
//
// nix runs with nothing of the session's environment but what it needs to
// reach its store -- NIX_REMOTE, NIX_LOG_DIR, the container's
// configuration and no user's -- HOME, the CA bundle frisket's, and a PATH
// of nix and git alone; for apps.nix.timeout. A flake is evaluated purely,
// its nixConfig never taken and its lock never written; a shell.nix under
// restrict-eval, its NIX_PATH the system's nixpkgs and the checkout.
// Every fetch is the session's own, through its network. An evaluation
// that met a path of the lower the host is substituting at that moment --
// which the session may not change the mode of -- is tried again, after
// 1, 3 and 9 s.
//
// Its variables are given to the agent behind every one the session has
// already, which are flong's, the container's and chase's, those that lost
// said by name; nix develop's own, those that steer bash, and those that
// steer the agent are not given at all, the last said (parse).
//
// A devShell that cannot be evaluated is said, and the agent started
// without it; in mode granted -- the grant asked for it -- it ends the
// session with status 125 instead, before the agent starts.
func Inside(ctx context.Context, args, environ []string, stderr io.Writer) int {
	var o inside
	fs := flag.NewFlagSet("chase-devshell", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.checkout, "checkout", "", "the checkout")
	fs.StringVar(&o.kind, "kind", "", "flake.nix or shell.nix")
	fs.StringVar(&o.nixpkgs, "nixpkgs", "", "<nixpkgs> to a shell.nix")
	fs.StringVar(&o.system, "system", "", "the devShells.<system> of a flake")
	fs.StringVar(&o.mode, "mode", "automatic", "automatic or granted")
	fs.StringVar(&o.nix, "nix", "", "the session's nix")
	fs.StringVar(&o.git, "git", "", "the git nix fetches with")
	fs.IntVar(&o.timeout, "timeout", 1200, "seconds the evaluation may take")
	front := fs.String("front", "", "PATH's first entries, ':'-separated")
	keep := fs.String("keep", "", "the names a devShell may not set, ' '-separated")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	o.front = split(*front)
	o.keep = strings.Fields(*keep)
	argv := fs.Args()
	switch {
	case len(argv) == 0:
		fmt.Fprintln(stderr, "chase-devshell: no agent to run after --")
		return 2
	case o.kind != flake && o.kind != shell, !filepath.IsAbs(o.checkout), !filepath.IsAbs(o.nix), !filepath.IsAbs(o.git),
		o.mode != "automatic" && o.mode != "granted", o.timeout <= 0:
		fmt.Fprintln(stderr, "chase-devshell: its data is not what exec gives it")
		return 2
	}
	env := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			if _, seen := env[k]; !seen {
				env[k] = v
			}
		}
	}

	term.Say(stderr, "%s: evaluating the devShell of %s in the session", o.checkout, o.kind)
	ds, err := o.evaluate(ctx, env, stderr)
	if err != nil {
		var no *none
		reason := err.Error()
		if errors.As(err, &no) {
			reason = no.line
		}
		if o.mode == "granted" {
			term.Say(stderr, "%s: the devShell the grant asks for could not be evaluated, and the session ends: %s", o.checkout, reason)
			return Granted
		}
		term.Say(stderr, "%s: the devShell could not be evaluated, and the session starts without it: %s", o.checkout, reason)
		return execAgent(argv, environ, stderr)
	}

	// The devShell's variables, behind every one the session has.
	keepSet := map[string]bool{}
	for _, k := range o.keep {
		keepSet[k] = true
	}
	out := slices.Clone(environ)
	var overridden []string
	for _, v := range ds.Env {
		have, set := env[v.Name]
		if set || keepSet[v.Name] || strings.HasPrefix(v.Name, "TINI_") {
			if set && have != v.Value {
				overridden = append(overridden, v.Name)
			}
			continue
		}
		out = append(out, v.Name+"="+v.Value)
	}
	if len(overridden) > 0 {
		slices.Sort(overridden)
		term.Say(stderr, "%s: the devShell's %s %s the session's own", o.checkout, strings.Join(overridden, ", "), plural(len(overridden), "is", "are"))
	}
	return execAgent(session.Wrap(argv, ds, o.front, o.keep), out, stderr)
}

// execAgent execs argv, its program found on the session's PATH, never the
// devShell's: what is run is the session's own agent, or the bash that
// runs it.
func execAgent(argv, environ []string, stderr io.Writer) int {
	prog, err := exec.LookPath(argv[0])
	if err != nil {
		fmt.Fprintf(stderr, "chase-devshell: %s: not found\n", argv[0])
		return 127
	}
	err = syscall.Exec(prog, argv, environ)
	fmt.Fprintf(stderr, "chase-devshell: %s: %v\n", prog, err)
	return 126
}

// passed are the session's variables nix is given, where the session has
// them: what reaches its store, and the CA bundle a fetch trusts --
// frisket's, in a session whose egress is frisket's.
var passed = []string{"NIX_REMOTE", "NIX_LOG_DIR", "NIX_USER_CONF_FILES", "NIX_CONF_DIR",
	"HOME", "TMPDIR", "NIX_SSL_CERT_FILE", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"}

// sessionC0 is what each of nix's runs in a session is given first: flakes,
// and nothing the flake says of nix's own configuration.
var sessionC0 = []string{
	"--extra-experimental-features", "nix-command flakes",
	"--option", "accept-flake-config", "false",
}

// args are nix's, for the devShell's kind: print-dev-env, no profile,
// since a session's store keeps nothing past it.
func (o *inside) args() []string {
	a := append(slices.Clone(sessionC0), "print-dev-env", "--json")
	if o.kind == flake {
		return append(a, "--no-write-lock-file", o.checkout+"#devShells."+o.system+".default")
	}
	return append(a, "--option", "restrict-eval", "true", "--option", "allowed-uris", strings.Join(shellURIs, " "),
		"--arg", "inNixShell", "true", "-f", o.checkout+"/"+shell)
}

// lowerBusy is what nix says of a path of the lower the host is
// substituting while the session's store reads it: the session may not
// change its mode.
var lowerBusy = regexp.MustCompile(`(/nix/store/[0-9a-z]{32}-[^'"\s:]+)[^\n]*Operation not permitted`)

// evaluate is the devShell nix prints, parsed: tried again on lowerBusy,
// after each of backoff.
func (o *inside) evaluate(ctx context.Context, env map[string]string, stderr io.Writer) (*session.DevShell, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(o.timeout)*time.Second)
	defer cancel()
	nixEnv := []string{"PATH=" + filepath.Dir(o.nix) + ":" + filepath.Dir(o.git)}
	for _, k := range passed {
		if v, ok := env[k]; ok {
			nixEnv = append(nixEnv, k+"="+v)
		}
	}
	if o.kind == shell {
		nixEnv = append(nixEnv, "NIX_PATH=nixpkgs="+o.nixpkgs+":"+o.checkout)
	}
	for try := 0; ; try++ {
		out, err := o.nixRun(ctx, nixEnv, stderr)
		if err == nil {
			ds, dropped, err := parse(out)
			if err != nil {
				return nil, err
			}
			if len(dropped) > 0 {
				term.Say(stderr, "%s: the devShell's %s %s not given to the agent", o.checkout, strings.Join(dropped, ", "), plural(len(dropped), "is", "are"))
			}
			return ds, nil
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("it took more than %d s", o.timeout)
		}
		var f *failure
		if !errors.As(err, &f) {
			return nil, err
		}
		if o.kind == flake && strings.Contains(f.said, "does not provide attribute") {
			return nil, &none{line: fmt.Sprintf("flake.nix has no devShells.%s.default", o.system)}
		}
		m := lowerBusy.FindStringSubmatch(f.said)
		if m == nil {
			return nil, errors.New(hinted(f.reason))
		}
		if try == len(backoff) {
			return nil, fmt.Errorf("%s is still being substituted by the host, which the session's store waits on: %s", m[1], f.reason)
		}
		term.Say(stderr, "%s: %s is being substituted by the host; trying again in %s", o.checkout, m[1], backoff[try])
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff[try]):
		}
	}
}

// nixRun is one run of the session's nix: its stdin nothing, what it prints
// returned, and what it says on stderr, cleaned, as it comes; its process
// group killed when ctx is done.
func (o *inside) nixRun(ctx context.Context, env []string, stderr io.Writer) ([]byte, error) {
	cmd := exec.CommandContext(ctx, o.nix, o.args()...)
	cmd.Env = env
	cmd.Dir = o.checkout
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	var out, said bytes.Buffer
	lines := &cleanLines{w: stderr}
	cmd.Stdout = &out
	cmd.Stderr = io.MultiWriter(lines, &said)
	err := cmd.Run()
	lines.flush()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &failure{reason: reasonOf(said.String(), err), said: said.String()}
	}
	return out.Bytes(), nil
}
