package grant_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/grant"
	"github.com/danielbodart/chase/internal/session"
)

// What to record is read from the environment `chase record` sets, and a
// word that is not one of its own is refused rather than read as the
// nearest: a default of "always" is no default, and a base of "" is the
// tier.
func TestARecordingIsReadFromItsEnvironment(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	tok := strings.Repeat("ab", 16)
	r, err := grant.RecordingFromEnv(env(map[string]string{grant.EnvDefault: "allow", grant.EnvToken: tok}))
	if err != nil || r != (grant.Recording{Default: "allow", Base: "tier", Token: tok}) {
		t.Errorf("%+v, %v", r, err)
	}
	r, err = grant.RecordingFromEnv(env(map[string]string{grant.EnvBase: "none"}))
	if err != nil || r != (grant.Recording{Base: "none"}) {
		t.Errorf("a person's recording from scratch is %+v, %v", r, err)
	}
	for _, bad := range []map[string]string{
		{grant.EnvDefault: "always"},
		{grant.EnvDefault: "Allow"},
		{grant.EnvBase: "everything"},
		{grant.EnvToken: "../../x"},
		{grant.EnvToken: strings.Repeat("AB", 16)},
	} {
		if r, err := grant.RecordingFromEnv(env(bad)); err == nil {
			t.Errorf("%v was read as %+v", bad, r)
		}
	}
}

// A RECORDING'S SECCOMPPOLICY is approve's, the grant asked about as for
// any launch, with flong's lines for learning after it: every call the
// filter would refuse allowed and logged, but what the grant denies, which
// stays denied; from scratch, the lines apply to Hot and the grant's own
// allow alone. And the session's name is left where the `chase record`
// waiting on it looks.
func TestARecordingLearnsWhatTheFilterWouldRefuse(t *testing.T) {
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m0", "trusted", `{"seccomp": {"allow": ["io_uring_setup", "read"], "deny": ["ptrace"]}}`)
	tok := strings.Repeat("0f", 16)
	var errb bytes.Buffer
	r, err := grant.ApproveRecording(context.Background(), h.cfg, ws, "m1", "trusted", grant.Recording{Base: "tier", Token: tok}, &errb)
	if err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if got, want := r.Lines(), "allow io_uring_setup read\ndeny ptrace\nlog @known\nnolog ptrace\n"; got != want {
		t.Errorf("against the tier, it printed %q, not %q", got, want)
	}
	if got := read(t, h.cfg.Runtime+"/chase/.record/"+tok+".machine"); got != "m1\n" {
		t.Errorf("the session was announced as %q", got)
	}
	if fi, _ := os.Stat(h.cfg.Runtime + "/chase/.record"); fi == nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the tokens' directory is %v", fi)
	}
	if !h.isStaged("m1") {
		t.Error("nothing was staged for exec")
	}

	r, err = grant.ApproveRecording(context.Background(), h.cfg, ws, "m2", "trusted", grant.Recording{Base: "none"}, &errb)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(r.Lines(), "\n")
	allow := strings.Fields(lines[1])
	if lines[0] != "base none" || allow[0] != "allow" || !slices.Equal(allow[1:len(grant.Hot)+1], grant.Hot) ||
		!slices.Equal(allow[len(grant.Hot)+1:], []string{"io_uring_setup"}) ||
		!slices.Equal(lines[2:], []string{"deny ptrace", "log @known", "nolog ptrace", ""}) {
		t.Errorf("from scratch, it printed %q", r.Lines())
	}

	// A checkout with no grant learns against the tier alone.
	bare := h.root() + "/bare"
	h.checkout(bare)
	r, err = grant.ApproveRecording(context.Background(), h.cfg, bare, "m3", "trusted", grant.Recording{Base: "tier"}, &errb)
	if err != nil || r.Lines() != "log @known\n" {
		t.Errorf("with no grant, it printed %q, %v", r.Lines(), err)
	}

	// A grant that is not approved is not recorded either.
	t.Setenv(refuseAll, "1")
	write(t, ws+"/chase.jsonc", `{"seccomp": {"allow": ["bpf"]}}`)
	h.fx.Run("-C", ws, "add", "chase.jsonc")
	if _, err := grant.ApproveRecording(context.Background(), h.cfg, ws, "m4", "trusted", grant.Recording{Base: "tier", Token: tok}, &errb); err == nil {
		t.Error("an unapproved grant was recorded")
	}
	if got := read(t, h.cfg.Runtime+"/chase/.record/"+tok+".machine"); got != "m1\n" {
		t.Errorf("a launch that was refused announced itself: %q", got)
	}
}

// A RECORDING'S EXEC writes the session's document as any launch's, with
// frisket's record block in it: the default, and the sink in frisket's
// record directory named for the session, which frisket loads. The tier's
// lists and the grant's names are there as ever; a recording only decides
// what they would refuse.
func TestARecordingsDocumentHasItsRecordBlock(t *testing.T) {
	h := newHarness(t)
	h.cfg.RecordDir = "/var/lib/frisket/records"
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": ["api.github.com"], "routes": []}`)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m1", "trusted", `{"network": {"allow": ["registry.npmjs.org", "*.pythonhosted.org"]}}`)
	s := session.Config{Home: h.cfg.Home, Tiers: map[string]session.Tier{"trusted": {}}}
	var out, errb bytes.Buffer
	rec := grant.Recording{Default: "allow", Base: "tier"}
	if rc := grant.ExecRecording(context.Background(), s, &h.cfg, nil, rec, "trusted", ws, "m1", "", []string{"shell"}, &out, &errb); rc != 0 {
		t.Fatalf("exec failed: %s", errb.String())
	}
	path := h.dir + "/run/chase/m1/policy.json"
	var doc struct {
		Name   string          `json:"name"`
		Allow  []string        `json:"allow"`
		Record json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal([]byte(read(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	json.Compact(&compact, doc.Record)
	if got, want := compact.String(), `{"default":"allow","sink":"/var/lib/frisket/records/m1.jsonl"}`; got != want {
		t.Errorf("the record block is %s, not %s", got, want)
	}
	if !slices.Equal(doc.Allow, []string{"*.pythonhosted.org", "api.github.com", "registry.npmjs.org"}) {
		t.Errorf("the grant's names were not added: %q", doc.Allow)
	}
	frisketCheck(t, path)
	if got := grant.RecordSink(h.cfg, "m1"); got != "/var/lib/frisket/records/m1.jsonl" {
		t.Errorf("the sink is %q", got)
	}

	// A person's answers: no default, and with no directory the journal
	// alone.
	h.cfg.RecordDir = ""
	h.approved(ws, "m2", "trusted", "")
	out.Reset()
	if rc := grant.ExecRecording(context.Background(), s, &h.cfg, nil, grant.Recording{Base: "tier"}, "trusted", ws, "m2", "", []string{"shell"}, &out, &errb); rc != 0 {
		t.Fatalf("exec failed: %s", errb.String())
	}
	if !strings.Contains(read(t, h.dir+"/run/chase/m2/policy.json"), `"record": {}`) {
		t.Errorf("a person's recording has no empty record block: %s", read(t, h.dir+"/run/chase/m2/policy.json"))
	}

	// An ordinary launch has none.
	h.approved(ws, "m3", "trusted", "")
	if rc := grant.Exec(context.Background(), s, &h.cfg, nil, "trusted", ws, "m3", "", []string{"shell"}, io.Discard, &errb); rc != 0 {
		t.Fatalf("exec failed: %s", errb.String())
	}
	if strings.Contains(read(t, h.dir+"/run/chase/m3/policy.json"), "record") {
		t.Error("an ordinary launch's document records")
	}

	// A tier that takes no grant has no document of chase's to record in.
	errb.Reset()
	if rc := grant.ExecRecording(context.Background(), s, nil, nil, rec, "trusted", ws, "m4", "", []string{"shell"}, io.Discard, &errb); rc == 0 || !strings.Contains(errb.String(), "takes no grant") {
		t.Errorf("a tier with no grant recorded: %d %s", rc, errb.String())
	}
}

// A GRANT'S NETWORK is names, as frisket's allowlist holds them, added to
// the session's: exact names and *.suffix, never "*" -- every name, which
// only a tier says -- nor an address, nor one twice. One that names nothing
// is approved as none.
func TestAGrantsNetworkIsNames(t *testing.T) {
	for _, bad := range []string{
		`{"network": {"allow": ["*"]}}`,
		`{"network": {"allow": ["10.0.0.1"]}}`,
		`{"network": {"allow": ["Example.com"]}}`,
		`{"network": {"allow": ["a..b"]}}`,
		`{"network": {"allow": ["a.example", "a.example"]}}`,
		`{"network": {"allow": ["*.*.example"]}}`,
		`{"network": {"allow": ["host:443"]}}`,
		`{"network": {"deny": ["a.example"]}}`,
	} {
		if _, err := grant.ParseFile([]byte(bad)); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	b, err := grant.ParseFile([]byte(`{"network": {"allow": ["registry.npmjs.org", "*.pythonhosted.org"]}}`))
	if err != nil || string(b) != `{"apps":{},"network":{"allow":["registry.npmjs.org","*.pythonhosted.org"]}}` {
		t.Errorf("%s, %v", b, err)
	}
	h := newHarness(t)
	ws := h.root() + "/w"
	h.checkout(ws)
	h.approved(ws, "m1", "trusted", `{"network": {}}`)
	h.approved(ws, "m2", "trusted", `{"network": {"allow": []}}`)
	if asked := h.approvals(); len(asked) != 1 {
		t.Errorf("a network that names nothing was asked about again: %d", len(asked))
	}
	// A tier that allows every name is left as it is.
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": ["*"], "routes": []}`)
	h.launched(ws, "m3", "trusted", `{"network": {"allow": ["a.example"]}}`)
	if d := h.policyDoc("m3"); !slices.Equal(d.Allow, []string{"*"}) {
		t.Errorf("every name became %q", d.Allow)
	}
}
