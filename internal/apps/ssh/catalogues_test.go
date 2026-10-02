package ssh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/frisket/policy"
)

// deviceCatalogue is a device's own catalogue, as chase.apps.ssh.catalogues
// puts one in the store: a modem's CLI, with topics of its own, a read, a
// write, an arg operation making the read stricter, a guarded command and
// a secret of its own -- a password given as an argument.
func deviceCatalogue(t *testing.T, ops []Operation) string {
	t.Helper()
	if ops == nil {
		ops = []Operation{
			{ID: "dsl-info", Summary: "Show the DSL line", Class: "read", Category: "dsl", Commands: []string{"xdslctl info **"}},
			{ID: "dsl-reset", Summary: "Reset the DSL counters", Class: "write", Category: "dsl", Commands: []string{"xdslctl info **"}, Args: []string{"--reset"}},
			{ID: "wan-show", Summary: "Show the WAN", Class: "read", Category: "wan", Commands: []string{"wan show"}},
			{ID: "wan-manage", Summary: "Change the WAN", Class: "guarded", Category: "wan", Commands: []string{"wan editintf **"}},
			{ID: "factory-reset", Summary: "Reset to defaults", Class: "guarded", Category: "system", Commands: []string{"sys atcr **"}},
			{ID: "ping", Summary: "Ping a host", Class: "write", Category: "diagnostics", Commands: []string{"ping **"}},
			{ID: "credential-argument", Summary: "Give a password as an argument", Class: "guarded", Category: "secrets", Args: []string{"*password*"}},
		}
	}
	b, err := json.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "device.json")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// withCatalogue is withHosts(hosts), offering the device catalogue as
// zyxel.
func withCatalogue(t *testing.T, hosts map[string]TierHost) Config {
	c := withHosts(hosts)
	c.Catalogues = map[string]string{"zyxel": deviceCatalogue(t, nil)}
	return c
}

// A MACHINE'S OWN CATALOGUE (docs/apps/ssh.md): a machine that names one of
// chase.apps.ssh.catalogues is decided by it alone, in place of the Linux
// catalogue -- the tier's answers by its classes as ever, its own secrets,
// and what it does not name unmatched, `cat` and an SSH key's path too --
// while a machine beside it naming none is decided by Linux's.
func TestAMachineNamingACatalogueIsDecidedByItAlone(t *testing.T) {
	c := withCatalogue(t, map[string]TierHost{
		"modem":  tierHost(t, "192.168.1.1", `{"passwordFile": "/run/secrets/modem-password", "shell": true, "catalogue": "zyxel"}`),
		"server": tierHost(t, "10.0.0.4", ""),
	})
	routes, err := c.TierRoutes("trusted")
	if err != nil {
		t.Fatal(err)
	}
	modem, server := routes[0], routes[1]
	for _, tc := range []struct {
		route    policy.SSHRoute
		commands []string
		want     []string
	}{
		{modem,
			[]string{"xdslctl info --show", "xdslctl info --show --reset", "wan show", "ping 1.1.1.1", "wan editintf x", "sys atcr", "sys atcr reboot", "ping password", "cat /etc/passwd", "cat .ssh/id_rsa", "uptime", "ls; rm x"},
			[]string{"allow", "ask", "allow", "ask", "refuse", "refuse", "refuse", "refuse", "ask", "ask", "ask", "refuse"}},
		{server,
			[]string{"uptime", "cat .ssh/id_rsa", "xdslctl info --show"},
			[]string{"allow", "refuse", "ask"}},
	} {
		got := make([]string, len(tc.commands))
		for i, command := range tc.commands {
			got[i] = decide(tc.route, command)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q answered %q, not %q", tc.route.Name, tc.commands, got, tc.want)
		}
		if friskets := frisketDecide(t, tc.route, tc.commands); !slices.Equal(friskets, tc.want) {
			t.Errorf("%s: frisket answered %q with %q, not %q", tc.route.Name, tc.commands, friskets, tc.want)
		}
	}
	if out, err := frisketCheck(t, routes); err != nil {
		t.Fatalf("frisket refused the routes: %v: %s", err, out)
	}

	// The machine's lists name the catalogue's own ids and topics, and none
	// of Linux's.
	for _, tc := range []struct{ members, said string }{
		{`{"catalogue": "zyxel", "allow": ["category:wan", "dsl-reset"]}`, ""},
		{`{"catalogue": "zyxel", "allow": ["category:navigate"]}`, "category:navigate is no category of the catalogue's"},
		{`{"catalogue": "zyxel", "allow": ["list-directory"]}`, `"list-directory" is no operation of the catalogue's`},
		{`{"allow": ["category:wan"]}`, "category:wan is no category of the catalogue's"},
	} {
		c := withCatalogue(t, map[string]TierHost{"modem": tierHost(t, "192.168.1.1", tc.members)})
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
}

// What a machine's catalogue is held to: a name chase.apps.ssh.catalogues
// offers, never a path, and a catalogue CheckCatalogue holds whole, said of
// the tier's machine that names it at every launch of the tier.
func TestAMachinesCatalogueIsANameTheMachineOffers(t *testing.T) {
	broken := deviceCatalogue(t, []Operation{{ID: "Show", Summary: "s", Class: "read", Category: "dsl", Commands: []string{"show"}}})
	for _, tc := range []struct {
		catalogue  string
		catalogues map[string]string
		said       string
	}{
		{"zyxel", nil, `hosts.server.catalogue: "zyxel" is no catalogue chase.apps.ssh.catalogues offers: it offers none`},
		{"cisco", map[string]string{"zyxel": deviceCatalogue(t, nil), "draytek": deviceCatalogue(t, nil)}, "it offers draytek, zyxel"},
		{"/home/alice/zyxel.json", map[string]string{"zyxel": deviceCatalogue(t, nil)}, `hosts.server.catalogue: "/home/alice/zyxel.json" is not a catalogue's name`},
		{"zyxel", map[string]string{"zyxel": broken}, `hosts.server.catalogue: ` + broken + `: operation 0 (Show): id "Show" is not kebab-case`},
		{"zyxel", map[string]string{"zyxel": "/nonexistent/zyxel.json"}, "hosts.server.catalogue: open /nonexistent/zyxel.json"},
	} {
		c := withHosts(map[string]TierHost{"server": tierHost(t, "10.0.0.4", `{"catalogue": "`+tc.catalogue+`"}`)})
		c.Catalogues = tc.catalogues
		if _, err := c.TierRoutes("trusted"); err == nil || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("the tier's machine %s: %v, not %q", tc.catalogue, err, tc.said)
		}
	}
}

// A grant never names a catalogue: its machine is decided by the Linux
// catalogue whatever the machine offers. Were it otherwise, a grant naming
// a device's catalogue for a Linux machine would take every Linux secret, write
// and guarded rule off it -- cat ~/.ssh/id_ed25519 allowed, rm -rf ~ allowed
// under "unmatched": "allow" -- on one line its approver would have to
// know the meaning of. It is refused as the grant is read, as a credential
// is, so it is never approved nor launched.
func TestAGrantNamesNoCatalogue(t *testing.T) {
	c := config()
	c.Catalogues = map[string]string{"zyxel": deviceCatalogue(t, nil)}
	for _, extra := range []string{
		`{"catalogue": "zyxel"}`,
		`{"catalogue": "zyxel", "unmatched": "allow"}`,
		`{"catalogue": "zyxel", "allow": ["cat **"]}`,
	} {
		var b Binding
		if err := policy.Decode([]byte(binding(t, extra)), &b); err == nil || !strings.Contains(err.Error(), "catalogue") {
			t.Errorf("a grant naming a catalogue, %s, was read: %v", extra, err)
		}
		if _, _, err := prepare(t, c, "trusted", binding(t, extra)); err == nil {
			t.Errorf("a grant naming a catalogue, %s, was launched", extra)
		}
	}
	// And its Linux machine, offered a device's catalogue it does not name,
	// is decided by Linux's: the key and rm -rf refused, however wide
	// its own unmatched.
	r := route(t, c, `{"unmatched": "allow"}`)
	if got := []string{decide(r, "cat /home/dan/.ssh/id_ed25519"), decide(r, "rm -rf /home/dan"), decide(r, "uptime")}; !slices.Equal(got, []string{"refuse", "refuse", "allow"}) {
		t.Errorf("a grant's machine beside an offered catalogue answered %q", got)
	}
}

// The Linux catalogue's categories are a closed list, so that one misspelt
// is caught; a machine's own has topics of its own, each kebab-case.
func TestAMachinesCatalogueHasTopicsOfItsOwn(t *testing.T) {
	op := func(category string) []Operation {
		return []Operation{{ID: "a", Summary: "s", Class: "read", Category: category, Commands: []string{"a"}}}
	}
	if err := CheckCatalogue(op("wan"), nil); err != nil {
		t.Errorf("a device's topic: %v", err)
	}
	if err := CheckCatalogue(op("wan"), linuxCategories); err == nil || !strings.Contains(err.Error(), `category "wan" is not one of`) {
		t.Errorf("a topic Linux's does not have: %v", err)
	}
	for _, category := range []string{"WAN", "", "wan_adv", "category:wan"} {
		if err := CheckCatalogue(op(category), nil); err == nil || !strings.Contains(err.Error(), "is not kebab-case") {
			t.Errorf("%q: %v", category, err)
		}
	}
}

// When the system is built, every catalogue the machine offers is checked
// whole, whether a machine names it or not, and so is every tier's own
// machine, as its launch would check it.
func TestTheMachinesOwnSSHIsCheckedWhenTheSystemIsBuilt(t *testing.T) {
	broken := deviceCatalogue(t, []Operation{{ID: "show", Summary: "s", Class: "read", Category: "dsl", Commands: []string{"show  x"}}})
	ok := withCatalogue(t, map[string]TierHost{"modem": tierHost(t, "192.168.1.1", `{"catalogue": "zyxel", "allow": ["dsl-reset"]}`)})
	if err := ok.Check(); err != nil {
		t.Fatalf("a machine with a modem: %v", err)
	}
	for _, tc := range []struct {
		edit func(*Config)
		said string
	}{
		{func(c *Config) { c.Catalogues["spare"] = broken }, "chase.apps.ssh.catalogues.spare: " + broken + ": operation 0 (show): pattern"},
		{func(c *Config) { c.Catalogues["Spare"] = deviceCatalogue(t, nil) }, `chase.apps.ssh.catalogues: "Spare" is not kebab-case`},
		{func(c *Config) { c.Catalogue = "/nonexistent/operations.json" }, "catalogue: open /nonexistent/operations.json"},
		{func(c *Config) {
			tier := c.Tiers["trusted"]
			h := tier.Hosts["modem"]
			h.Allow = []string{"list-directory"}
			tier.Hosts["modem"] = h
		}, `chase.tiers.trusted.apps.ssh.hosts.modem: "list-directory" is no operation of the catalogue's`},
	} {
		c := withCatalogue(t, map[string]TierHost{"modem": tierHost(t, "192.168.1.1", `{"catalogue": "zyxel"}`)})
		tc.edit(&c)
		if err := c.Check(); err == nil || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("%v, not %q", err, tc.said)
		}
	}
}

// A tier's machine's expect pins its catalogue's answers when the system is
// built: each command answered as it says passes, and any answered
// otherwise fails the build, every such command said together, so that an
// edit to a catalogue that lets through what it refused is seen whole.
func TestATierMachinesExpectIsCheckedWhenTheSystemIsBuilt(t *testing.T) {
	modem := func(expect string) Config {
		return withCatalogue(t, map[string]TierHost{"modem": tierHost(t, "192.168.1.1", `{"catalogue": "zyxel", "shell": true, "expect": `+expect+`}`)})
	}
	if err := modem(`{"xdslctl info --show": "allow", "xdslctl info --show --reset": "ask", "sys atcr": "refuse", "cat /etc/passwd": "ask", "xdslctl info --show; reboot": "refuse"}`).Check(); err != nil {
		t.Errorf("a modem answering as it expects: %v", err)
	}
	err := modem(`{"xdslctl info --show --reset": "refuse", "cat /etc/passwd": "allow", "wan show": "allow"}`).Check()
	for _, said := range []string{
		`chase.tiers.trusted.apps.ssh.hosts.modem.expect: `,
		`"cat /etc/passwd" is answered ask, not allow`,
		`"xdslctl info --show --reset" is answered ask, not refuse`,
	} {
		if err == nil || !strings.Contains(err.Error(), said) {
			t.Errorf("a modem answering otherwise: %v, not %q", err, said)
		}
	}
	if err != nil && strings.Contains(err.Error(), "wan show") {
		t.Errorf("a command answered as expected was said: %v", err)
	}
	if err := modem(`{"wan show": "deny"}`).Check(); err == nil || !strings.Contains(err.Error(), `"wan show" expects "deny", not one of allow, ask, refuse`) {
		t.Errorf("an answer no route gives: %v", err)
	}
}
