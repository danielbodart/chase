package devshell

import (
	"slices"
	"strings"
	"testing"
)

// OFFLINE: a tier whose egress is not direct and unfiltered, someone
// else's code. Its devShell, which the approved grant turns on as in any
// tier, is realised with no network.
func offline(t *testing.T) *harness {
	h := newHarness(t)
	h.n.Offline = true
	return h
}

// Four runs, each with no network and substitution back on: the
// derivation evaluated alone, nothing built while it is; read; its inputs
// substituted, as the outputs it takes and never ^*, with no local build;
// and print-dev-env of it, the one build nix's record of its environment.
func TestOfflineTheDevShellIsEvaluatedReadSubstitutedAndRecorded(t *testing.T) {
	h := offline(t)
	h.checkout(map[string]string{"shell.nix": "{}"})
	ds, err := h.realise()
	if err != nil || ds == nil || ds.Path[0] != "/nix/store/hello/bin" {
		t.Fatalf("%+v, %v: %s", ds, err, h.said)
	}
	runs := h.runs("nix")
	if len(runs) != 4 {
		t.Fatalf("nix ran %d times", len(runs))
	}
	want := [][]string{
		{"eval", "--raw", "--option", "substitute", "true", "--max-jobs", "0", "--option", "allow-import-from-derivation", "false",
			"--option", "restrict-eval", "true", "--option", "allowed-uris", "",
			"--arg", "inNixShell", "true", "-f", h.r.Workspace + "/shell.nix", "drvPath"},
		{"derivation", "show", "--option", "substitute", "true", shellDrv},
		{"build", "--no-link", "--option", "substitute", "true", "--max-jobs", "0",
			"/nix/store/5c6c4dzr5fyk9vcrig229yxr9yidbl0c-hello-2.12.3.drv^out",
			"/nix/store/yrk6i9db8wc7bjhqf71brv62w2nr6dw2-webkitgtk-2.48.drv^dev,out"},
		{"print-dev-env", "--json", "--option", "substitute", "true", "--max-jobs", "1", "--profile", h.r.Dir + "/devshell/profile", shellDrv + "^*"},
	}
	for i, r := range runs {
		if a := args(r); !slices.Equal(a, want[i]) {
			t.Errorf("run %d is %q, not %q", i, a, want[i])
		}
	}
	for i, r := range h.runs("bwrap") {
		argv := r.Argv[:slices.Index(r.Argv, "--")]
		if slices.Contains(argv, "--share-net") || !slices.Contains(argv, "--unshare-all") {
			t.Errorf("bwrap run %d has a network: %q", i, argv)
		}
	}
	if !slices.Contains(runs[0].Env, "HOME="+h.r.State+"/devshell/offline-home") {
		t.Errorf("nix's HOME is one's own code's: %q", runs[0].Env)
	}
	h.mustSay("realising the devShell of shell.nix, with no network")
	if strings.Contains(h.said, "Internet access") {
		t.Errorf("nix's warning that it has no network was said: %s", h.said)
	}
	// And cached, as one's own code's is.
	h.clear()
	if ds, err := h.realise(); ds == nil || err != nil || h.runs("nix") != nil {
		t.Errorf("again: %+v, %v, ran %d", ds, err, len(h.runs("nix")))
	}
}

// A flake's derivation is its devShells.<system>.default's, evaluated
// purely, its lock never written; one with none has none, as online.
func TestOfflineAFlakesDerivationIsItsDefaultDevShells(t *testing.T) {
	h := offline(t)
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if _, err := h.realise(); err != nil {
		t.Fatalf("%v: %s", err, h.said)
	}
	want := []string{"eval", "--raw", "--option", "substitute", "true", "--max-jobs", "0", "--option", "allow-import-from-derivation", "false",
		"--no-write-lock-file", h.r.Workspace + "#devShells.x86_64-linux.default.drvPath"}
	if a := args(h.runs("nix")[0]); !slices.Equal(a, want) {
		t.Errorf("a flake was evaluated with %q, not %q", a, want)
	}

	h = offline(t)
	h.k.NoDefault = true
	h.checkout(map[string]string{"flake.nix": flakeNix, "flake.lock": githubLock})
	if ds, err := h.realise(); ds != nil || err != nil {
		t.Errorf("no default: %+v, %v", ds, err)
	}
	h.mustSay("flake.nix has no devShells.x86_64-linux.default")
}

// What cannot be realised offline refuses the launch, as it does online,
// and is tried again at the next, as a failure is: a fetch, said with
// what this tier gives a devShell; an input in none of the machine's
// binary caches, before anything is built; a derivation that asks for
// what a sandboxed build is not given, before anything is substituted.
func TestOfflineWhatCannotBeRealisedRefusesTheLaunch(t *testing.T) {
	for _, c := range []struct {
		what, at, said, derivation, want string
		runs                             int
	}{
		{"a fetch", "eval", "error: access to URI 'https://example.com/' is forbidden in restricted mode", "",
			"access to URI 'https://example.com/' is forbidden in restricted mode; a devShell is realised with no network in this tier", 1},
		{"a local build", "build", "error: Cannot build '/nix/store/b3nfnbcvcvk5jnlwyyrvjxvyyq4ib748-x.drv'.\n       Reason: local builds are disabled (max-jobs = 0)", "",
			"what it needs is not all in the machine's binary caches, and nothing of a devShell is built in this tier but nix's record of its environment: Cannot build", 3},
		{"__noChroot", "", "", strings.Replace(shellDerivation, `"name":"nix-shell"`, `"name":"nix-shell","__noChroot":"1"`, 1),
			"the devShell asks nix for __noChroot, which a sandboxed build is not given", 2},
	} {
		h := offline(t)
		h.checkout(map[string]string{"shell.nix": "{}"})
		h.k.Fail, h.k.FailAt, h.k.FailSaid = c.at != "", c.at, c.said
		if c.derivation != "" {
			h.k.Derivation = c.derivation
		}
		ds, err := h.realise()
		h.mustRefuse(ds, err, c.want)
		if n := len(h.runs("nix")); n != c.runs {
			t.Errorf("%s: nix ran %d times, not %d", c.what, n, c.runs)
		}
		h.clear()
		ds, err = h.realise()
		h.mustRefuse(ds, err, c.want)
		if n := len(h.runs("nix")); n != c.runs {
			t.Errorf("%s again: nix ran %d times, not %d", c.what, n, c.runs)
		}
	}
}

// What a derivation asks for that a sandboxed build is not given, in its
// environment or its structured attributes; and what of its inputs nix
// is asked to substitute, in the format of nix before 2.33 too.
func TestWhatADerivationIsReadFor(t *testing.T) {
	drv := "/nix/store/lfqsxafsv6plq2hi64arbqi3q3d4qgmk-nix-shell.drv"
	show := func(d string) []byte {
		return []byte(`{"derivations":{"lfqsxafsv6plq2hi64arbqi3q3d4qgmk-nix-shell.drv":` + d + `}}`)
	}
	for d, want := range map[string]string{
		`{"env":{"__impure":"1"}}`:                                          "__impure",
		`{"env":{"__noChroot":""}}`:                                         "",
		`{"env":{"requiredSystemFeatures":"kvm recursive-nix"}}`:            "the system feature recursive-nix",
		`{"env":{"__json":"{\"requiredSystemFeatures\":[\"uid-range\"]}"}}`: "the system feature uid-range",
		`{"env":{},"structuredAttrs":{"__noChroot":true}}`:                  "__noChroot",
		`{"env":{"requiredSystemFeatures":"kvm big-parallel"}}`:             "",
	} {
		_, err := inputsOf(drv, show(d))
		switch {
		case want == "" && err != nil:
			t.Errorf("%s was refused: %v", d, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), "asks nix for "+want)):
			t.Errorf("%s: %v", d, err)
		}
	}
	old := `{"/nix/store/lfqsxafsv6plq2hi64arbqi3q3d4qgmk-nix-shell.drv":{"env":{},"inputDrvs":{"/nix/store/5c6c4dzr5fyk9vcrig229yxr9yidbl0c-hello-2.12.3.drv":["out","man"]}}}`
	if in, err := inputsOf(drv, []byte(old)); err != nil || !slices.Equal(in, []string{"/nix/store/5c6c4dzr5fyk9vcrig229yxr9yidbl0c-hello-2.12.3.drv^man,out"}) {
		t.Errorf("before 2.33: %q, %v", in, err)
	}
	for what, d := range map[string]string{
		"another derivation":  `{"derivations":{"5c6c4dzr5fyk9vcrig229yxr9yidbl0c-hello-2.12.3.drv":{"env":{}}}}`,
		"an input not a drv":  string(show(`{"env":{},"inputs":{"drvs":{"--option.drv":{"outputs":["out"]}}}}`)),
		"an output an option": string(show(`{"env":{},"inputs":{"drvs":{"5c6c4dzr5fyk9vcrig229yxr9yidbl0c-hello-2.12.3.drv":{"outputs":["-x"]}}}}`)),
		"dynamic outputs":     string(show(`{"env":{},"inputs":{"drvs":{"5c6c4dzr5fyk9vcrig229yxr9yidbl0c-hello-2.12.3.drv":{"outputs":[],"dynamicOutputs":{"out":{"outputs":["out"]}}}}}}`)),
	} {
		if in, err := inputsOf(drv, []byte(d)); err == nil {
			t.Errorf("%s was read: %q", what, in)
		}
	}
}
