package ssh

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/policy"
)

// tierHost is a tier's machine at address, with members merged over it.
func tierHost(t *testing.T, address, members string) TierHost {
	t.Helper()
	h := TierHost{Host: Host{Address: address, User: "admin", HostKeys: []string{hostKey(t, address)}}}
	if members != "" {
		if err := json.Unmarshal([]byte(members), &h); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// withHosts is config() with these machines the trusted tier's own.
func withHosts(hosts map[string]TierHost) Config {
	c := config()
	tier := c.Tiers["trusted"]
	tier.Hosts = hosts
	c.Tiers["trusted"] = tier
	return c
}

// A TIER'S OWN MACHINES (docs/apps/ssh.md): each is an SSH route in every
// session of the tier, decided by the catalogue, the tier and its own lists
// as a grant's machine is, and logging in with its own credential -- an
// agent, a key file or a password file -- or, naming none, the machine's.
// A shell host is a shell route, with no env taken off its commands. What
// it logs in with is a path, and nothing else of the credential is in the
// route.
func TestATiersOwnMachinesAreRoutesWithTheirOwnCredentials(t *testing.T) {
	c := withHosts(map[string]TierHost{
		"server":  tierHost(t, "10.0.0.4", `{"user": "core", "refuse": ["category:packages"]}`),
		"gateway": tierHost(t, "10.0.0.1", `{"user": "root", "agent": "/run/user/1000/other/ssh", "identity": "SHA256:`+strings.Repeat("A", 43)+`"}`),
		"modem":   tierHost(t, "192.168.1.1", `{"passwordFile": "/run/secrets/modem-password", "shell": true}`),
	})
	routes, err := c.TierRoutes("trusted")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, r := range routes {
		names = append(names, r.Name)
	}
	if !slices.Equal(names, []string{"gateway", "modem", "server"}) {
		t.Fatalf("not the tier's machines in name order: %q", names)
	}
	gateway, modem, server := routes[0], routes[1], routes[2]
	if gateway.Agent != "/run/user/1000/other/ssh" || gateway.Identity == "" || gateway.KeyFile != "" || gateway.PasswordFile != "" {
		t.Errorf("the gateway does not log in with its own agent: %+v", gateway)
	}
	if server.Agent != "/run/user/1000/gcr/ssh" || server.User != "core" || server.Address != "10.0.0.4" || !slices.Equal(server.Env, defaultEnv) {
		t.Errorf("the server does not log in with the machine's agent: %+v", server)
	}
	if modem.PasswordFile != "/run/secrets/modem-password" || modem.Agent != "" || modem.Identity != "" || !modem.Shell || modem.Env != nil {
		t.Errorf("the modem is not a shell route logging in with its password file: %+v", modem)
	}
	if out, err := frisketCheck(t, routes); err != nil {
		t.Fatalf("frisket refused the tier's machines: %v: %s", err, out)
	}

	// Each decided as a grant's machine is, by its own lists: the modem's
	// own commands are no catalogue's, and are asked about, and what a
	// shell route cannot read is refused, never asked: it would be typed
	// into the device byte for byte.
	for _, tc := range []struct {
		route    policy.SSHRoute
		commands []string
		want     []string
	}{
		{server, []string{"uptime", "apt list --installed", "rm -rf /"}, []string{"allow", "refuse", "refuse"}},
		{modem, []string{"xdslctl info --show", "uptime", "ls; rm x", "xdslctl info --show\rreboot"}, []string{"ask", "allow", "refuse", "refuse"}},
	} {
		if got := frisketDecide(t, tc.route, tc.commands); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q answered %q, not %q", tc.route.Name, tc.commands, got, tc.want)
		}
	}

	// A machine with no credential of its own needs none of its own.
	if routes, err := (Config{Tiers: c.Tiers, Catalogue: catalogue, KeyFile: "/home/alice/.ssh/k"}).TierRoutes("trusted"); err != nil || routes[2].KeyFile != "/home/alice/.ssh/k" || routes[2].Agent != "" {
		t.Errorf("the server does not log in with the machine's key file: %v %+v", err, routes)
	}
	// A tier with none, or no SSH, has no route.
	for _, tier := range []string{"plain"} {
		if routes, err := c.TierRoutes(tier); err != nil || routes != nil {
			t.Errorf("%s has routes: %v %+v", tier, err, routes)
		}
	}
	if routes, err := config().TierRoutes("trusted"); err != nil || routes != nil {
		t.Errorf("a tier with no machines has routes: %v %+v", err, routes)
	}
}

// What a tier's machine is held to: everything a grant's is, said of where
// the tier names it, and what it logs in with -- one path, absolute and
// clean, never in the store or under /tmp, an identity with an agent alone,
// and the machine's credential where it names none.
func TestATiersMachineIsHeldToWhatAGrantsIsAndOneCredential(t *testing.T) {
	for _, tc := range []struct{ members, said string }{
		{`{"address": "modem.lan"}`, "chase.tiers.trusted.apps.ssh.hosts.modem.address"},
		{`{"hostKeys": []}`, "chase.tiers.trusted.apps.ssh.hosts.modem.hostKeys: none"},
		{`{"allow": ["restart-everything"]}`, `chase.tiers.trusted.apps.ssh.hosts.modem: "restart-everything" is no operation of the catalogue's`},
		{`{"agent": "/run/a", "passwordFile": "/run/p"}`, "modem: agent and passwordFile: frisket logs in with one of"},
		{`{"keyFile": "/run/k", "passwordFile": "/run/p"}`, "keyFile and passwordFile"},
		{`{"passwordFile": "run/secrets/p"}`, "modem.passwordFile: \"run/secrets/p\" is not an absolute path"},
		{`{"passwordFile": "/run/secrets/../p"}`, "is not a clean path"},
		{`{"keyFile": "/nix/store/x-key"}`, "is in the store"},
		{`{"passwordFile": "/tmp/p"}`, "PrivateTmp"},
		{`{"passwordFile": "/run/p", "identity": "SHA256:` + strings.Repeat("A", 43) + `"}`, "modem.identity names a key of the host's own agent"},
		{`{"agent": "/run/a", "identity": "SHA256:short"}`, "is not a key's fingerprint"},
		{`{"shell": true, "allow": ["xdslctl info **"]}`, ""},
	} {
		c := withHosts(map[string]TierHost{"modem": tierHost(t, "192.168.1.1", tc.members)})
		_, err := c.TierRoutes("trusted")
		if tc.said == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.members, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("%s: %v, not %q", tc.members, err, tc.said)
		}
	}
	// Naming none, the machine's is used, and a machine with none, or
	// both, has nothing to log in with.
	for _, c := range []Config{{Catalogue: catalogue}, {Catalogue: catalogue, Agent: "/run/a", KeyFile: "/run/k"}} {
		c.Tiers = withHosts(map[string]TierHost{"modem": tierHost(t, "192.168.1.1", "")}).Tiers
		if _, err := c.TierRoutes("trusted"); err == nil || !strings.Contains(err.Error(), "modem names no agent, keyFile or passwordFile") {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// A grant adds machines to the tier's, and never names one again: one of
// the same name, or at the same address, is refused when the grant is
// approved and again at launch. A grant's machine still needs the
// machine's credential, which a tier's own machines do not.
func TestAGrantNeverNamesATiersMachineAgain(t *testing.T) {
	c := withHosts(map[string]TierHost{"server": tierHost(t, "192.168.1.10", "")})
	for _, tc := range []struct{ binding, said string }{
		{binding(t, `{"address": "192.168.1.11"}`), "apps.ssh.hosts.server is the tier's own machine"},
		{`{"hosts": {"other": {"address": "192.168.1.10:22", "user": "ops", "hostKeys": ["` + hostKey(t, "o") + `"]}}}`, "apps.ssh.hosts.other.address: 192.168.1.10:22 is the tier's own server"},
	} {
		var b Binding
		if err := policy.Decode([]byte(tc.binding), &b); err != nil {
			t.Fatal(err)
		}
		if err := c.CheckBinding("trusted", b); err == nil || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("approved %s: %v", tc.binding, err)
		}
		if _, _, err := prepare(t, c, "trusted", tc.binding); err == nil || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("launched %s: %v", tc.binding, err)
		}
	}
	other := `{"hosts": {"other": {"address": "192.168.1.11", "user": "ops", "hostKeys": ["` + hostKey(t, "o") + `"]}}}`
	if p, _, err := prepare(t, c, "trusted", other); err != nil || len(p.SSH) != 1 || p.SSH[0].Name != "other" {
		t.Errorf("a grant's own machine beside the tier's: %v %+v", err, p.SSH)
	}
	// A grant's machine logs in with the machine's credential; a binding
	// naming none does not need one.
	c.Agent = ""
	if _, _, err := prepare(t, c, "trusted", other); err == nil || !strings.Contains(err.Error(), "exactly one of chase.apps.ssh.agentSocket and keyFile") {
		t.Errorf("a grant's machine with no credential: %v", err)
	}
	if p, _, err := prepare(t, c, "trusted", `{}`); err != nil || len(p.SSH) != 0 {
		t.Errorf("a binding of no machine: %v %+v", err, p.SSH)
	}
	// A grant cannot name a credential: what a tier's machine logs in with
	// is the tier's alone.
	var b Binding
	if err := policy.Decode([]byte(`{"hosts": {"other": {"address": "192.168.1.11", "user": "ops", "hostKeys": [], "passwordFile": "/home/alice/.ssh/id_ed25519"}}}`), &b); err == nil {
		t.Error("a grant named a password file")
	}
}
