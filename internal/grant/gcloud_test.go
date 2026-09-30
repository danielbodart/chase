package grant_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/apps"
	appsgcloud "github.com/danielbodart/chase/internal/apps/gcloud"
	renew "github.com/danielbodart/chase/internal/gcloud"
	"github.com/danielbodart/chase/internal/gcloud/gcloudtest"
	"github.com/danielbodart/chase/internal/grant"
)

// The launcher-level parts of the ported gcloud-launch check (the prepare's
// own are internal/apps/gcloud's): GOOGLE CLOUD AT LAUNCH, bound with the
// project's own key, decrypted by sops from the approved file; its routes
// merged into the tier's document and the project's lists applied to them;
// the renewer started by systemctl, with the user's runtime directory; and,
// at the session's end, stopped before the directory its key is in goes.
func TestGoogleCloudIsLaunchedAndStoppedWithItsSession(t *testing.T) {
	h := newHarness(t)
	const sa = "agent@p.iam.gserviceaccount.com"
	catalogue, err := filepath.Abs(filepath.Join("..", "..", "apps", "gcloud"))
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Gcloud = &appsgcloud.Config{
		Tiers: map[string]appsgcloud.Tier{
			"trusted": {Writes: "ask", Guarded: "refuse", Unmatched: "ask", APIs: []string{"bigquery", "storage"}},
		},
		Catalogue:   catalogue,
		Every:       []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"},
		Placeholder: "proxy-injected",
		RuntimeDir:  h.cfg.Runtime,
		Systemctl:   h.dir + "/bin/systemctl",
	}
	var minted []string
	var said strings.Builder
	app := appsgcloud.New(*h.cfg.Gcloud, &said)
	app.Mint = func(_ context.Context, run, account string) renew.Outcome {
		minted = append(minted, account+" mint "+run)
		os.WriteFile(filepath.Join(run, "gcloud-token.json"), []byte(`{"access_token": "t", "expiry": 1}`), 0o600)
		return renew.Minted
	}
	h.registry = map[string]apps.App{"gcloud": app}
	// The tier has a gcloud route of its own, which the app's replaces
	// rather than joins: `merge.jq`'s patch, applied by the launch.
	write(t, h.cfg.Policies+"/trusted.json", `{"name": "trusted", "allow": ["github.com"], "routes": [{"name": "gcloud", "host": "x", "upstream": "https://x"}]}`)

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secrets, _ := json.Marshal(map[string]string{"gcloud-key": string(gcloudtest.Key(k, sa, "p"))})
	ws := h.root() + "/w"
	h.checkout(ws)
	write(t, ws+"/secrets.json", string(secrets))
	h.fx.Run("-C", ws, "add", "secrets.json")
	h.launched(ws, "m1", "trusted", `{"secrets": "secrets.json", "bindings": {"gcloud": {
		"serviceAccount": "`+sa+`", "credential": {"secret": "gcloud-key"},
		"apis": {"add": ["pubsub"], "remove": ["storage"]},
		"allow": ["category:bigquery"], "ask": ["pubsub.projects.topics.delete"]}}}`)
	run := h.dir + "/run/chase/m1"
	if !h.said("chase: " + ws + ": gcloud from secrets.json:gcloud-key") {
		t.Errorf("where gcloud came from was not said: %s", h.err)
	}
	if !slices.Equal(minted, []string{sa + " mint " + run}) {
		t.Errorf("no first token was minted: %q", minted)
	}
	if log := h.log("systemctl.log"); !slices.Equal(log, []string{h.cfg.Runtime + " --user start chase-gcloud-renew@m1.service"}) {
		t.Errorf("the renewer was not started: %q", log)
	}
	d := h.policyDoc("m1")
	var names []string
	for _, r := range d.Routes {
		names = append(names, r.Name)
	}
	if !slices.Equal(names, []string{"gcloud", "gcloud-mtls"}) || !slices.Equal(d.Allow, []string{"*.googleapis.com", "github.com"}) {
		t.Fatalf("the routes were not merged: %q %q", names, d.Allow)
	}
	if d.Routes[0].Host != "*.googleapis.com" {
		t.Errorf("the tier's gcloud route was not replaced by the app's: %s", d.Routes[0].Host)
	}
	if d.Routes[0].CredentialFile != run+"/gcloud-token.json" {
		t.Errorf("the route does not carry the session's token: %s", d.Routes[0].CredentialFile)
	}
	answer := func(id string) string {
		for _, r := range d.Routes[0].Paths {
			if r.Operation != nil && r.Operation.ID == id {
				switch {
				case r.Refuse:
					return "refuse"
				case r.Ask:
					return "ask"
				}
				return "allow"
			}
		}
		return "absent"
	}
	for id, want := range map[string]string{
		"bigquery.datasets.get":                                       "allow",
		"bigquery.datasets.insert":                                    "allow",
		"bigquery.datasets.delete":                                    "allow",
		"pubsub.projects.topics.delete":                               "ask",
		"iamcredentials.projects.serviceAccounts.generateAccessToken": "refuse",
	} {
		if got := answer(id); got != want {
			t.Errorf("%s is answered %s, not %s", id, got, want)
		}
	}
	// The key is kept in the checkout's own directory, and the session is
	// given a copy in its home, which its environment names.
	env := h.env()
	if len(env) != 2 || len(h.given.Files) != 1 {
		t.Fatalf("the session was not given its key: %q %+v", env, h.given.Files)
	}
	seeded := h.given.Files[0]
	if env[0] != "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE="+seeded.Path || env[1] != "GOOGLE_APPLICATION_CREDENTIALS="+seeded.Path {
		t.Errorf("the session's environment does not name its key: %q", env)
	}
	if !strings.HasPrefix(seeded.Path, h.dir+"/home/.config/chase/gcloud-key-") || seeded.Mode != 0o600 {
		t.Errorf("the session's key is not the user's own, in its home: %+v", seeded)
	}
	if kept := read(t, h.dir+"/state/checkouts/"+key(ws)+"/"+filepath.Base(seeded.Path)); kept != seeded.Content {
		t.Error("the session's key is not the checkout's")
	}
	frisketCheck(t, run+"/policy.json")

	// The session's end: the renewer stopped, while the key it signs with
	// is still there, and then the session's directory gone.
	if rc := grant.RunPostStop(context.Background(), h.cfg, h.registry, []string{"m1"}, nil, &strings.Builder{}, &strings.Builder{}); rc != 0 {
		t.Fatalf("postStop failed: %d", rc)
	}
	if log := h.log("systemctl.log"); len(log) != 2 || log[1] != h.cfg.Runtime+" --user stop chase-gcloud-renew@m1.service" {
		t.Errorf("postStop did not stop the renewer first: %q", log)
	}
	if _, err := os.Stat(run); err == nil {
		t.Error("the session's directory outlived it")
	}

	// LISTS THAT DO NOT APPLY end the launch: a category of an API this
	// session does not carry -- storage, removed -- is the script's `||
	// die`, said after why, and nothing of the session is written or given.
	h.approved(ws, "m2", "trusted", `{"secrets": "secrets.json", "bindings": {"gcloud": {
		"serviceAccount": "`+sa+`", "credential": {"secret": "gcloud-key"},
		"apis": {"remove": ["storage"]}, "allow": ["category:storage"]}}}`)
	if rc := h.launch("trusted", ws, "m2"); rc != 1 {
		t.Fatalf("lists that do not apply were launched: %d %s", rc, h.err)
	}
	if want := "chase: gcloud has no category:storage\nchase: " + ws + ": its gcloud lists do not apply\n"; !strings.HasSuffix(h.err, want) {
		t.Errorf("the refusal said %q, not %q", h.err, want)
	}
	if _, err := os.Stat(h.dir + "/run/chase/m2/policy.json"); err == nil {
		t.Error("a document was written for lists that do not apply")
	}
	if len(h.given.Env) != 0 || len(h.given.Files) != 0 {
		t.Errorf("the session was given %+v for lists that do not apply", h.given)
	}
}
