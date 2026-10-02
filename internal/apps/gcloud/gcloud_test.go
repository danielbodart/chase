package gcloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/chase/internal/files"
	renew "github.com/danielbodart/chase/internal/gcloud"
	"github.com/danielbodart/chase/internal/gcloud/gcloudtest"
)

// The ported gcloud-launch check (docs/gcloud.md, decisions 2, 3, 5 and 9):
// the tier's APIs and the project's changes to them, answered as the tier
// says; the session's key, made once and never the real one; the first
// token and the renewer; against the committed catalogue. The minter and
// systemd are stand-ins that say what they were asked.

const sa = "agent@p.iam.gserviceaccount.com"

var every = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

// catalogue is the committed apps/gcloud, as the module passes it.
func catalogue(t *testing.T) string {
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "apps", "gcloud"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The tiers of the check: examples/tiers.nix's trusted with BigQuery and
// Storage; a loose one that allows what is unmatched and guarded; and a
// closed one that carries nothing and refuses everything.
func config(t *testing.T) Config {
	return Config{
		Tiers: map[string]Tier{
			"trusted": {Writes: "ask", Guarded: "refuse", Unmatched: "ask", APIs: []string{"bigquery", "storage"}},
			"loose":   {Writes: "ask", Guarded: "allow", Unmatched: "allow", APIs: []string{"bigquery"}},
			"closed":  {Writes: "refuse", Guarded: "refuse", Unmatched: "refuse", APIs: []string{}},
		},
		Catalogue:   catalogue(t),
		Every:       every,
		Placeholder: "proxy-injected",
		RuntimeDir:  "/run/user/1000",
		Systemctl:   "/nonexistent/systemctl",
	}
}

// units says what it was asked, as the check's systemctl did.
type units struct {
	mu  sync.Mutex
	log []string
	err error
}

func (u *units) Start(_ context.Context, unit string) error { return u.record("start " + unit) }
func (u *units) Stop(_ context.Context, unit string) error  { return u.record("stop " + unit) }
func (u *units) record(s string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.log = append(u.log, s)
	return u.err
}

type launch struct {
	t      *testing.T
	app    *App
	units  *units
	minted []string
	rc     renew.Outcome
	stderr bytes.Buffer
	dir    string
	real   *rsa.PrivateKey
}

var (
	realOnce sync.Once
	realKey  *rsa.PrivateKey
)

func newLaunch(t *testing.T) *launch {
	realOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		realKey = k
	})
	l := &launch{t: t, units: &units{}, dir: t.TempDir(), real: realKey}
	l.app = &App{Config: config(t), Stderr: &l.stderr, Units: l.units}
	l.app.Mint = func(_ context.Context, run, sa string) renew.Outcome {
		l.minted = append(l.minted, sa+" mint "+run)
		os.WriteFile(filepath.Join(run, "gcloud-token.json"), []byte(`{"access_token": "t", "expiry": 1}`), 0o600)
		return l.rc
	}
	return l
}

// session is a run directory whose secret is the real key, for email.
func (l *launch) session(machine, email string) string {
	run := filepath.Join(l.dir, "run", machine)
	if err := os.MkdirAll(filepath.Join(run, "secrets"), 0o700); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "secrets", "gcloud"), realKeyFile(l.real, email), 0o600); err != nil {
		l.t.Fatal(err)
	}
	return run
}

func realKeyFile(k *rsa.PrivateKey, email string) []byte {
	var m map[string]any
	json.Unmarshal(gcloudtest.Key(k, email, "p"), &m)
	m["private_key_id"] = "real"
	b, _ := json.Marshal(m)
	return b
}

func binding(apis string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"serviceAccount": %q, "credential": {"secret": "gcloud-key"}, "apis": %s}`, sa, apis))
}

func (l *launch) prepare(tier, run string, b json.RawMessage) (apps.Patch, error) {
	return l.app.Prepare(context.Background(), apps.Request{
		Tier: tier, Workspace: "/ws", Run: run, Dir: filepath.Join(l.dir, "checkout"), Home: filepath.Join(l.dir, "home"), Binding: b,
	})
}

func (l *launch) prepared(tier, run string, b json.RawMessage) apps.Patch {
	l.t.Helper()
	p, err := l.prepare(tier, run, b)
	if err != nil {
		l.t.Fatalf("a binding was not prepared: %v", err)
	}
	return p
}

func route(t *testing.T, p apps.Patch, name string) policy.Route {
	t.Helper()
	for _, r := range p.Routes {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no route %s", name)
	return policy.Route{}
}

// answer is how the gcloud route answers an operation: its first rule's.
func answer(t *testing.T, p apps.Patch, id string) string {
	for _, r := range route(t, p, "gcloud").Paths {
		if r.Operation != nil && r.Operation.ID == id {
			switch {
			case r.Refuse:
				return "refuse"
			case r.Ask:
				return "ask"
			default:
				return "allow"
			}
		}
	}
	return "absent"
}

// What returns a credential, of APIs the check's tiers carry and do not.
var credentials = []string{
	"bigquery.batch", "iamcredentials.projects.serviceAccounts.generateAccessToken",
	"google.iam.credentials.v1.IAMCredentials.SignJwt", "sts.token", "iam.projects.serviceAccounts.keys.create",
	"storage.projects.hmacKeys.create", "secretmanager.projects.secrets.versions.access",
	"google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
	"contactcenterinsights.projects.locations.conversations.generateSignedAudio",
	"google.cloud.edgecontainer.v1.EdgeContainer.GenerateAccessToken",
}

func TestTheRouteCarriesTheTiersAPIsWithTheProjectsChanges(t *testing.T) {
	l := newLaunch(t)
	run := l.session("chase-trusted-1-2", sa)
	patch := l.prepared("trusted", run, binding(`{"add": ["pubsub"], "remove": ["storage"]}`))
	r := route(t, patch, "gcloud")

	var carried []string
	for _, p := range r.Paths {
		if p.Operation != nil && p.Operation.Category != "" {
			carried = append(carried, p.Operation.Category)
		}
	}
	slices.Sort(carried)
	if carried = slices.Compact(carried); !slices.Equal(carried, []string{"bigquery", "google.iam.v1.IAMPolicy", "pubsub"}) {
		t.Errorf("the APIs are not the tier's with the project's changes: %q", carried)
	}
	seen := map[string]bool{}
	for _, p := range r.Paths {
		k := fmt.Sprintf("%q %q %q", p.Methods, p.Path, p.Prefix)
		if seen[k] {
			t.Errorf("a rule is there twice: %s", k)
		}
		seen[k] = true
	}
	if r.Unmatched != "ask" || r.CredentialFile != run+"/gcloud-token.json" ||
		r.CredentialJSON == nil || *r.CredentialJSON != (policy.CredentialJSON{Token: "access_token", ExpiresMillis: "expiry"}) ||
		r.Host != "*.googleapis.com" || r.Upstream != "https://*.googleapis.com" || r.Placeholder != "proxy-injected" ||
		r.SessionKey == nil || r.SessionKey.Issuer != sa ||
		!slices.Equal(r.SessionKey.Grants, []string{"oauth2.googleapis.com/token", "www.googleapis.com/oauth2/v4/token"}) {
		r.Paths = nil
		t.Errorf("the route is not Google's: %+v", r)
	}
	if r.Refusal == nil || r.Refusal.ContentType != "application/json" ||
		r.Refusal.Body != `{"error":{"code":403,"message":"{{message}}","status":"PERMISSION_DENIED"}}` {
		t.Errorf("the refusal is not Google's envelope: %+v", r.Refusal)
	}
	m := route(t, patch, "gcloud-mtls")
	if m.Host != "*.mtls.googleapis.com" || m.Upstream != "https://*.mtls.googleapis.com" || len(m.Paths) != 1 ||
		!m.Paths[0].Refuse || m.Paths[0].Prefix != "/" || !slices.Equal(m.Paths[0].Methods, every) ||
		m.CredentialFile != "" || m.Unmatched != "refuse" {
		t.Errorf("the mtls hosts are not refused whole: %+v", m)
	}
	if !slices.Equal(patch.Allow, []string{"*.googleapis.com"}) {
		t.Errorf("allow is %q", patch.Allow)
	}
	for id, want := range map[string]string{
		"bigquery.datasets.get":         "allow",
		"bigquery.datasets.insert":      "ask",
		"pubsub.projects.topics.delete": "refuse",
		// The project removed it, and it is no guarded operation.
		"storage.objects.get": "absent",
	} {
		if got := answer(t, patch, id); got != want {
			t.Errorf("%s is %s, not %s", id, got, want)
		}
	}
}

// Every API's guarded operations are in the route, carried or not, answered
// as the tier's guarded says: what returns a credential too, and a carried
// API's "*" does not decide them.
func TestTheFloorIsEveryAPIsGuardedOperations(t *testing.T) {
	l := newLaunch(t)
	patch := l.prepared("trusted", l.session("chase-trusted-1-2", sa), binding(`{"add": ["pubsub"], "remove": ["storage"]}`))
	for _, id := range append(slices.Clone(credentials), "storage.buckets.delete", "compute.instances.delete") {
		if got := answer(t, patch, id); got != "refuse" {
			t.Errorf("%s is %s, not refused by default", id, got)
		}
	}
	found := false
	for _, p := range route(t, patch, "gcloud").Paths {
		if p.Path == "/v1/projects/*/locations/*/conversations/*:generateSignedAudio" && p.Methods[0] == "GET" {
			found = true
			if !p.Refuse {
				t.Error("another API's signed audio is not refused")
			}
		}
		if p.Operation != nil && p.Operation.ID == "iamcredentials.projects.serviceAccounts.generateAccessToken" &&
			(p.Operation.Category != "" || p.Operation.Description != "") {
			t.Errorf("an API the session does not carry has a category in it: %+v", p.Operation)
		}
	}
	if !found {
		t.Error("another API's signed audio is not in the route")
	}
}

func TestTheSessionsKeyIsTheCheckoutsAndNeverTheRealOne(t *testing.T) {
	l := newLaunch(t)
	run := l.session("chase-trusted-1-2", sa)
	patch := l.prepared("trusted", run, binding(`{}`))
	// The session is given a copy of the checkout's key, seeded into its
	// home under the key's own name, and pointed at it.
	seeded := patch.Env["GOOGLE_APPLICATION_CREDENTIALS"]
	if m, _ := filepath.Match(filepath.Join(l.dir, "home", ".config", "chase", "gcloud-key-*.json"), seeded); !m {
		t.Fatalf("the key is not seeded into the session's home: %s", seeded)
	}
	if patch.Env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] != seeded {
		t.Error("gcloud is not given the key")
	}
	key := filepath.Join(l.dir, "checkout", filepath.Base(seeded))
	b, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("the key is not kept in the checkout's directory: %v", err)
	}
	if len(patch.Files) != 1 || patch.Files[0].Path != seeded || patch.Files[0].Mode != 0o600 || patch.Files[0].Content != string(b) {
		t.Errorf("the session is not given the checkout's key, the user's alone: %+v", patch.Files)
	}
	var k map[string]any
	json.Unmarshal(b, &k)
	if _, has := k["client_id"]; k["type"] != "service_account" || k["client_email"] != sa || k["project_id"] != "p" ||
		k["private_key_id"] == "real" || has {
		t.Errorf("the session's key is not the service account's shape: %v", keysOf(k))
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Errorf("the session's key is %v", fi.Mode().Perm())
	}
	public := route(t, patch, "gcloud").SessionKey.PublicKey
	if want := pubout(t, k["private_key"].(string)); public != want {
		t.Errorf("the route does not hold the session key's public half:\n%s\nnot\n%s", public, want)
	}
	if public == pubout(t, keyPEM(l.real)) {
		t.Error("the session holds the real key")
	}
	id := k["private_key_id"]
	l.prepared("trusted", run, binding(`{}`))
	b, _ = os.ReadFile(key)
	json.Unmarshal(b, &k)
	if k["private_key_id"] != id {
		t.Error("the checkout's key was made again")
	}
	if !slices.Contains(l.minted, sa+" mint "+run) {
		t.Errorf("no first token was minted: %q", l.minted)
	}
	if !slices.Contains(l.units.log, "start chase-gcloud-renew@chase-trusted-1-2.service") {
		t.Errorf("the renewer was not started: %q", l.units.log)
	}

	// Another account, launched from the same checkout, has a key of its
	// own and leaves this one's for the session that has it.
	other := l.session("chase-trusted-3-4", "other@p.iam.gserviceaccount.com")
	theirs := l.prepared("trusted", other, json.RawMessage(`{"serviceAccount": "other@p.iam.gserviceaccount.com", "credential": {"secret": "gcloud-key"}}`)).
		Env["GOOGLE_APPLICATION_CREDENTIALS"]
	tb, _ := os.ReadFile(filepath.Join(l.dir, "checkout", filepath.Base(theirs)))
	var tk map[string]any
	json.Unmarshal(tb, &tk)
	if theirs == seeded || tk["client_email"] != "other@p.iam.gserviceaccount.com" {
		t.Error("another account took this one's key")
	}
	b, _ = os.ReadFile(key)
	json.Unmarshal(b, &k)
	if k["private_key_id"] != id || k["client_email"] != sa {
		t.Error("another account's launch changed this one's key")
	}
}

// The key file is named, and written, as the script wrote it: a name from
// the account and project, jq's indentation, and a key openssl could have
// made.
func TestTheSessionsKeyFileIsTheScripts(t *testing.T) {
	dir := t.TempDir()
	// printf '%s %s' agent@p.iam.gserviceaccount.com p | sha256sum | cut -c1-16
	if got, want := keyPath(dir, sa, "p"), filepath.Join(dir, "gcloud-key-"+sha16(sa+" p")+".json"); got != want {
		t.Errorf("%s, want %s", got, want)
	}
	path, public, err := sessionKey(filepath.Join(dir, "env"), `a<b>&c@p.iam.gserviceaccount.com`, "p")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	for _, want := range []string{
		"{\n  \"type\": \"service_account\",\n  \"project_id\": \"p\",\n  \"private_key_id\": \"",
		"\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\n",
		"\\n-----END PRIVATE KEY-----\\n\",\n  \"client_email\": \"a<b>&c@p.iam.gserviceaccount.com\",\n" +
			"  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n" +
			"  \"token_uri\": \"https://oauth2.googleapis.com/token\",\n" +
			"  \"universe_domain\": \"googleapis.com\"\n}\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the key file does not hold %q:\n%s", want, s)
		}
	}
	var k sessionKeyFile
	json.Unmarshal(b, &k)
	if len(k.PrivateKeyID) != 40 || strings.Trim(k.PrivateKeyID, "0123456789abcdef") != "" {
		t.Errorf("private_key_id %q is not openssl rand -hex 20", k.PrivateKeyID)
	}
	if !strings.HasPrefix(public, "-----BEGIN PUBLIC KEY-----\n") || !strings.HasSuffix(public, "-----END PUBLIC KEY-----") {
		t.Errorf("the public half is not as openssl pkey -pubout gave it: %q", public)
	}
	if _, err := os.Stat(filepath.Join(dir, "env", ".gcloud-key.lock")); err != nil {
		t.Errorf("it was not made under the script's lock: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "env", ".lock")); err == nil {
		t.Error("it took envdir's own lock")
	}
	// A key of another project is another file; one that names another
	// account where this one's should be is made again.
	other, _, _ := sessionKey(filepath.Join(dir, "env"), `a<b>&c@p.iam.gserviceaccount.com`, "q")
	if other == path {
		t.Error("another project shares the key")
	}
	os.WriteFile(path, []byte(`{"client_email": "x", "project_id": "p"}`), 0o600)
	if _, _, err := sessionKey(filepath.Join(dir, "env"), `a<b>&c@p.iam.gserviceaccount.com`, "p"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if !strings.Contains(string(b), "BEGIN PRIVATE KEY") {
		t.Error("a key naming another account was kept")
	}
}

// Two launches of one checkout at once make one key between them.
func TestConcurrentLaunchesMakeOneKey(t *testing.T) {
	env := filepath.Join(t.TempDir(), "env")
	var wg sync.WaitGroup
	publics := make([]string, 4)
	for i := range publics {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, p, err := sessionKey(env, sa, "p")
			if err != nil {
				t.Error(err)
			}
			publics[i] = p
		}()
	}
	wg.Wait()
	for _, p := range publics[1:] {
		if p != publics[0] {
			t.Fatal("two launches made two keys")
		}
	}
}

// What is unmatched is allowed where the tier says so, and every guarded
// operation, what returns a credential too, is allowed where guarded is.
func TestALooseTierAllowsWhatItSays(t *testing.T) {
	l := newLaunch(t)
	loose := l.prepared("loose", l.session("chase-loose-1", sa), binding(`{}`))
	r := route(t, loose, "gcloud")
	last := r.Paths[len(r.Paths)-1]
	if !slices.Equal(last.Methods, every) || last.Prefix != "/" || last.Path != "" || last.Ask || last.Refuse || last.Operation != nil ||
		last.EncodedSlashes || r.Unmatched != "refuse" {
		t.Errorf("an unmatched allow has no catch-all: %+v, unmatched %q", last, r.Unmatched)
	}
	for _, id := range append([]string{"bigquery.datasets.delete"}, credentials...) {
		if got := answer(t, loose, id); got != "allow" {
			t.Errorf("%s is %s where guarded is allowed", id, got)
		}
	}
}

// A tier that carries no API and refuses everything still has a route, and
// refuses what returns a credential.
func TestAClosedTierRefusesTheFloor(t *testing.T) {
	l := newLaunch(t)
	closed := l.prepared("closed", l.session("chase-closed-1", sa), binding(`{}`))
	r := route(t, closed, "gcloud")
	if len(r.Paths) == 0 || r.Unmatched != "refuse" {
		t.Fatalf("the closed route has %d rules, unmatched %q", len(r.Paths), r.Unmatched)
	}
	for _, id := range credentials {
		if got := answer(t, closed, id); got != "refuse" {
			t.Errorf("%s is %s where nothing is carried", id, got)
		}
	}
	for _, p := range r.Paths {
		if p.Operation == nil || p.Operation.Class != "guarded" || !p.Refuse {
			t.Errorf("a tier that carries nothing has more than the floor: %+v", p)
		}
	}
	// What the patch is, frisket's decoder takes: no field it does not know.
	b, _ := json.Marshal(closed)
	var back struct {
		Routes []policy.Route    `json:"routes"`
		Allow  []string          `json:"allow"`
		Env    map[string]string `json:"env"`
	}
	if err := policy.Decode(b, &back); err != nil {
		t.Errorf("frisket's decoder refused the patch: %v", err)
	}
}

// Refused: an API with no name, a key for someone else, and Google refusing
// the key. Google out of reach only warns.
func TestWhatEndsTheLaunch(t *testing.T) {
	for _, c := range []struct {
		what, needle, tier string
		binding            json.RawMessage
		rc                 renew.Outcome
	}{
		{"an unknown API", "no Google API named nope", "trusted", binding(`{"add": ["nope"]}`), 0},
		{"unknown APIs, all named", "no Google API named nope, nah", "trusted", binding(`{"add": ["nope"], "remove": ["nah"]}`), 0},
		{"apis that are not lists", "its APIs do not resolve", "trusted", binding(`{"add": "pubsub"}`), 0},
		{"no service account", "no serviceAccount", "trusted", json.RawMessage(`{"credential": {"secret": "gcloud-key"}}`), 0},
		{"a key for another account", "/ws: gcloud: the key is for '" + sa + "', not other@p", "trusted",
			json.RawMessage(`{"serviceAccount": "other@p", "credential": {"secret": "gcloud-key"}}`), 0},
		{"a key Google refuses", "Google refused " + sa + "'s key: was it deleted or disabled?", "trusted", binding(`{}`), renew.Refused},
		{"a key the renewer finds is not the account's", "the key is not " + sa + "'s", "trusted", binding(`{}`), renew.BadKey},
		{"a renewer that fails otherwise", "the renewer failed (64)", "trusted", binding(`{}`), 64},
	} {
		l := newLaunch(t)
		l.rc = c.rc
		_, err := l.prepare(c.tier, l.session("chase-trusted-1-2", sa), c.binding)
		if err == nil {
			t.Errorf("%s was not refused", c.what)
		} else if !strings.Contains(err.Error(), c.needle) {
			t.Errorf("%s: expected %q in: %v", c.what, c.needle, err)
		}
		if c.rc != 0 && len(l.units.log) != 0 {
			t.Errorf("%s: the renewer was started", c.what)
		}
	}

	l := newLaunch(t)
	l.rc = renew.Transient
	if _, err := l.prepare("trusted", l.session("chase-trusted-1-2", sa), binding(`{}`)); err != nil {
		t.Errorf("Google out of reach ended the launch: %v", err)
	}
	if want := "chase: /ws: gcloud: no token yet, Google did not answer; the renewer keeps trying\n"; l.stderr.String() != want {
		t.Errorf("Google out of reach was said as %q", l.stderr.String())
	}
	if !slices.Contains(l.units.log, "start chase-gcloud-renew@chase-trusted-1-2.service") {
		t.Error("the renewer was not started to keep trying")
	}

	l = newLaunch(t)
	l.units.err = fmt.Errorf("no manager")
	if _, err := l.prepare("trusted", l.session("chase-trusted-1-2", sa), binding(`{}`)); err == nil ||
		err.Error() != "/ws: gcloud: could not start chase-gcloud-renew@chase-trusted-1-2" {
		t.Errorf("a renewer that did not start: %v", err)
	}
}

// The secret must be a service-account key, whatever the binding says.
func TestTheSecretMustBeAServiceAccountKey(t *testing.T) {
	for name, secret := range map[string]string{
		"none":           "",
		"not json":       "x",
		"an array":       "[]",
		"another type":   `{"type": "authorized_user", "private_key": "k", "client_email": "` + sa + `"}`,
		"no private key": `{"type": "service_account", "client_email": "` + sa + `"}`,
	} {
		l := newLaunch(t)
		run := l.session("m", sa)
		if secret == "" {
			os.Remove(filepath.Join(run, "secrets", "gcloud"))
		} else {
			os.WriteFile(filepath.Join(run, "secrets", "gcloud"), []byte(secret), 0o600)
		}
		if _, err := l.prepare("trusted", run, binding(`{}`)); err == nil || err.Error() != "/ws: gcloud: the secret is not a service-account key" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A tier without gcloud says so, and keeps no secret.
func TestATierWithoutGcloudIgnoresIt(t *testing.T) {
	l := newLaunch(t)
	run := l.session("chase-strict-1", sa)
	p, err := l.prepare("strict", run, binding(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(p); string(b) != "{}" {
		t.Errorf("a tier without gcloud prepared it: %s", b)
	}
	if _, err := os.Stat(filepath.Join(run, "secrets", "gcloud")); !os.IsNotExist(err) {
		t.Error("a tier without gcloud kept its secret")
	}
	if l.stderr.String() != "chase: /ws: gcloud ignored: strict has no gcloud\n" {
		t.Errorf("said %q", l.stderr.String())
	}
	if len(l.minted) != 0 || len(l.units.log) != 0 {
		t.Error("a tier without gcloud minted or started a renewer")
	}
}

// The session's end stops the renewer, if its launch kept a Google secret.
func TestStopStopsTheRenewerOfASessionWithASecret(t *testing.T) {
	l := newLaunch(t)
	l.app.Config.RuntimeDir = t.TempDir()
	os.MkdirAll(filepath.Join(l.app.Config.RuntimeDir, "chase", "chase-trusted-1-2", "secrets"), 0o700)
	os.WriteFile(filepath.Join(l.app.Config.RuntimeDir, "chase", "chase-trusted-1-2", "secrets", "gcloud"), []byte("{}"), 0o600)
	if err := l.app.Stop(context.Background(), "chase-trusted-1-2"); err != nil {
		t.Fatal(err)
	}
	if err := l.app.Stop(context.Background(), "chase-trusted-3-4"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(l.units.log, []string{"stop chase-gcloud-renew@chase-trusted-1-2.service"}) {
		t.Errorf("stopped %q", l.units.log)
	}
}

// systemctl is reached with XDG_RUNTIME_DIR, as the check's stand-in saw.
func TestSystemctlIsReachedWithTheRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "systemctl.log")
	bin := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\necho \"$XDG_RUNTIME_DIR $*\" >> " + log + "\n[ \"$2\" != stop ] || exit 5\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := Systemctl{Path: bin, RuntimeDir: "/run/user/1000", Output: &out}
	if err := s.Start(context.Background(), "chase-gcloud-renew@chase-trusted-1-2.service"); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(context.Background(), "chase-gcloud-renew@chase-trusted-1-2.service"); err == nil {
		t.Error("a failed stop was not said")
	}
	b, _ := os.ReadFile(log)
	if string(b) != "/run/user/1000 --user start chase-gcloud-renew@chase-trusted-1-2.service\n"+
		"/run/user/1000 --user stop chase-gcloud-renew@chase-trusted-1-2.service\n" {
		t.Errorf("systemctl was asked %q", b)
	}
}

// The whole launch, with the renewer's own mint against a fake Google that
// checks the grant: the first token is the session's, and the key is shown
// only to the fake.
func TestAPrepareMintsTheFirstTokenFromGoogle(t *testing.T) {
	l := newLaunch(t)
	google := gcloudtest.New(&l.real.PublicKey, sa)
	defer google.Close()
	l.app.Mint = nil
	l.app.Config.TokenURL = google.TokenURL()
	run := l.session("chase-trusted-1-2", sa)
	if _, err := l.prepare("trusted", run, binding(`{}`)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(run, "gcloud-token.json"))
	if log := google.Log(); len(log) != 1 || log[0].Code != 200 || !strings.Contains(string(b), log[0].Token) {
		t.Errorf("the first token is not Google's: %s, %+v", b, log)
	}
	if !strings.Contains(l.stderr.String(), "chase-gcloud-renew: minted for "+sa) {
		t.Errorf("said %q", l.stderr.String())
	}
	google.Answer(401)
	if _, err := l.prepare("trusted", run, binding(`{}`)); err == nil || !strings.Contains(err.Error(), "Google refused") {
		t.Errorf("a key Google refuses: %v", err)
	}
}

// fixedKey is a throwaway RSA-1024 test key that `openssl genpkey` made,
// and fixedPublic is what `openssl pkey -pubout` said of it, less the
// newline a command substitution drops. It guards nothing.
const (
	fixedKey = `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALrXYiwCe+OAYUVE
bocUSDSNXyInary9MonXti91pVcbBYzz68XPkZMMPlurv4KlT9iuVaGA/ce7QXGm
J5Q4mLFNDWy10HQyvhVoFV72n6BAxEGHKpOxVYDpe2Ap3SXhPWp0GEEFtGpQVaCC
ZsuFFSn4WxNQCGzNAapDRfkgKE4dAgMBAAECgYBULHZw50mTC6JGx3aX6l5BNrN2
OpXOo9nh2cmdBf5QCL9uafF9M28c9TYerHhhzkHzl07CrM8oLUdlgPpxvzGiYcM4
3qbM9hYALUFOvh288a4UNFD2U2YRKcrcYiM2v0Z0D1UjKxnlfL0vegEnfo0MIM3M
2kINcPSyH3YPtJp1rQJBAN5Y/6y6w5VufbOQgBZR1zGXyRaelGMwiBiR1dDEL8ft
uJnCt6R6EUgwpUBAOyz7HLuYNgWPd59EHrxZnpqgvQ8CQQDXHquRrzuJP1dx6nJp
aH2I2SoHHo9SMujPsrtfKWkVmTozP+YrsekWsBu8pMcXze9k9XOoANZshe5WBy3W
DVoTAkEAukJry9KYTPHGM0n1Qr1EO7MfLOei/oSFPa/NIZl3PVASuBu5ovruxz6Y
7/3elIu3Qh78AiRw3OY/qSCaEIZeWQJAdtLSIh6Q3DbIrnu5xs+Yx8ZsmJIgyF6m
ilNHfED7cpq4syZQlUIoZgfQylqaPmPaIAIUaHBOAJPaGlrMzreBUQJBAL2kB9um
s56jCRSQ27Skd++WzczP2E77hzULvGQ20o4scHi1BMZ28WoMl42ANQLAPl+U27Qj
Y1Dyxk8U0nbifNY=
-----END PRIVATE KEY-----
`
	fixedPublic = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC612IsAnvjgGFFRG6HFEg0jV8i
J2q8vTKJ17YvdaVXGwWM8+vFz5GTDD5bq7+CpU/YrlWhgP3Hu0FxpieUOJixTQ1s
tdB0Mr4VaBVe9p+gQMRBhyqTsVWA6XtgKd0l4T1qdBhBBbRqUFWggmbLhRUp+FsT
UAhszQGqQ0X5IChOHQIDAQAB
-----END PUBLIC KEY-----`
)

// The route's public half is byte for byte what openssl gave the script:
// PKIX, its header, its line breaks, and no newline at the end.
func TestThePublicHalfIsOpensslsForAFixedKey(t *testing.T) {
	b, _ := json.Marshal(map[string]string{"private_key": fixedKey})
	got, err := publicHalf(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixedPublic {
		t.Errorf("the public half is not openssl's:\n%q\nnot\n%q", got, fixedPublic)
	}
	if openssl := pubout(t, fixedKey); openssl != fixedPublic {
		t.Errorf("pubout is not openssl's:\n%q", openssl)
	}
}

// Nil Units is systemctl, from the module's Config: its path, and the
// user's runtime directory for XDG_RUNTIME_DIR, as the prepare ran it.
func TestAPrepareStartsTheRenewerWithTheConfiguredSystemctl(t *testing.T) {
	l := newLaunch(t)
	dir := t.TempDir()
	log := filepath.Join(dir, "systemctl.log")
	bin := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"$XDG_RUNTIME_DIR $*\" >> "+log+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	l.app.Units = nil
	l.app.Config.Systemctl = bin
	l.app.Config.RuntimeDir = "/run/user/1000"
	l.prepared("trusted", l.session("chase-trusted-1-2", sa), binding(`{}`))
	b, _ := os.ReadFile(log)
	if string(b) != "/run/user/1000 --user start chase-gcloud-renew@chase-trusted-1-2.service\n" {
		t.Errorf("systemctl was asked %q", b)
	}

	// A Config the module did not fill is said to be one, and ends the
	// launch as a failed start did.
	l.app.Config.Systemctl = ""
	if _, err := l.prepare("trusted", l.session("chase-trusted-1-2", sa), binding(`{}`)); err == nil ||
		!strings.Contains(err.Error(), "could not start chase-gcloud-renew@chase-trusted-1-2") {
		t.Errorf("a launch with no systemctl: %v", err)
	}
	if !strings.Contains(l.stderr.String(), "chase: gcloud: no systemctl, or no runtime directory, to start chase-gcloud-renew@chase-trusted-1-2.service with") {
		t.Errorf("said %q", l.stderr.String())
	}
}

// The key's lock is its own, as the script's .gcloud-key.lock was: a
// launcher holding envdir's lock around Prepare does not wait on itself.
func TestTheKeysLockIsItsOwn(t *testing.T) {
	env := filepath.Join(t.TempDir(), "env")
	os.MkdirAll(env, 0o700)
	unlock, err := files.Lock(env)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	done := make(chan error, 1)
	go func() {
		_, _, err := sessionKey(env, sa, "p")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the key waited on envdir's lock")
	}
	if _, err := os.Stat(filepath.Join(env, ".gcloud-key.lock")); err != nil {
		t.Errorf("the key was not made under its own lock: %v", err)
	}
}

func keysOf(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	slices.Sort(k)
	return k
}

func keyPEM(k *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// pubout is `openssl pkey -pubout` of a PEM private key, as a command
// substitution holds it: openssl's own where it is at hand, as the flake's
// check had it, so the route's public half is held to an implementation
// that is not publicHalf's. Without openssl it is worked out here, and
// TestThePublicHalfIsOpensslsForAFixedKey still holds publicHalf to
// openssl's bytes.
func pubout(t *testing.T, private string) string {
	t.Helper()
	if openssl, err := exec.LookPath("openssl"); err == nil {
		cmd := exec.Command(openssl, "pkey", "-pubout")
		cmd.Stdin = strings.NewReader(private)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("openssl pkey -pubout: %v", err)
		}
		return strings.TrimRight(string(out), "\n")
	}
	block, _ := pem.Decode([]byte(private))
	if block == nil {
		t.Fatal("no PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(k.(*rsa.PrivateKey).Public())
	return strings.TrimSuffix(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "\n")
}
