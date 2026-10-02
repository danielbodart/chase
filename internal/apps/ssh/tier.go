package ssh

import (
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/policy"
)

// TierHost is one machine a tier names for itself (apps/ssh.nix's
// chase.tiers.<name>.apps.ssh.hosts): a Host, held to everything a grant's
// is, and what frisket logs in to it with, which a grant never names -- a
// project naming a file to send as a password would send any file of the
// user's to a machine of its choosing. None of the three is the machine's
// chase.apps.ssh credential; more than one is refused. Identity is with an
// agent only.
//
// Catalogue too is the tier's alone: it names the one of
// chase.apps.ssh.catalogues this machine's commands are decided by, a
// device's own CLI, in place of the Linux catalogue, which decides a
// machine that names none -- and which a grant's machine is always decided
// by. A grant naming a device's catalogue for a Linux machine would take
// every Linux secret, write and guarded rule off it, cat ~/.ssh/id_ed25519 and
// rm -rf ~ with them, on one line of JSON its approver would have to read
// the meaning of.
//
// Expect is what the machine's commands must be answered, by command, when
// the system is built (Check): a catalogue's answers pinned where they
// matter -- what must be refused, what must not run unasked -- so that an
// edit to the catalogue, or to the tier, that changes one fails the build
// rather than a session.
type TierHost struct {
	Host
	Catalogue    string            `json:"catalogue,omitempty"`
	Expect       map[string]string `json:"expect,omitempty"`
	Agent        string            `json:"agent,omitempty"`
	KeyFile      string            `json:"keyFile,omitempty"`
	PasswordFile string            `json:"passwordFile,omitempty"`
	Identity     string            `json:"identity,omitempty"`
}

var fingerprint = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// storeDir is where Nix keeps what every user reads: no credential is
// ever there.
const storeDir = "/nix/store/"

// checkCredentialPath is apps/ssh.nix's pathProblem: a path the frisket
// daemon reaches as it is -- absolute and clean, with no working directory
// of the user's -- never in the store, which is everyone's to read, and
// never under a /tmp the daemon's PrivateTmp hides.
func checkCredentialPath(p string) error {
	switch {
	case !filepath.IsAbs(p) || strings.HasSuffix(p, "/"):
		return fmt.Errorf("%q is not an absolute path with nothing after its last /", p)
	case filepath.Clean(p) != p:
		return fmt.Errorf("%q is not a clean path", p)
	case strings.HasPrefix(p, storeDir):
		return fmt.Errorf("%q is in the store, which every user reads", p)
	case strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/var/tmp/"):
		return fmt.Errorf("%q is under a /tmp the frisket daemon's PrivateTmp hides", p)
	}
	return nil
}

// login is what frisket logs in to a tier's machine with: the host's own,
// or, where it names none, the machine's chase.apps.ssh. at names the host.
func (c Config) login(at string, h TierHost) (agent, keyFile, passwordFile, identity string, err error) {
	var named []string
	for _, f := range []struct{ field, path string }{{"agent", h.Agent}, {"keyFile", h.KeyFile}, {"passwordFile", h.PasswordFile}} {
		if f.path == "" {
			continue
		}
		named = append(named, f.field)
		if err := checkCredentialPath(f.path); err != nil {
			return "", "", "", "", fmt.Errorf("%s.%s: %w", at, f.field, err)
		}
	}
	switch {
	case len(named) > 1:
		return "", "", "", "", fmt.Errorf("%s: %s: frisket logs in with one of agent, keyFile and passwordFile", at, strings.Join(named, " and "))
	case h.Identity != "" && h.Agent == "":
		return "", "", "", "", fmt.Errorf("%s.identity names a key of the host's own agent, and it names no agent", at)
	case h.Identity != "" && !fingerprint.MatchString(h.Identity):
		return "", "", "", "", fmt.Errorf("%s.identity: %q is not a key's fingerprint, SHA256: and 43 characters of base64, as ssh-keygen -l prints it", at, h.Identity)
	case len(named) == 1:
		return h.Agent, h.KeyFile, h.PasswordFile, h.Identity, nil
	case (c.Agent == "") == (c.KeyFile == ""):
		return "", "", "", "", fmt.Errorf("%s names no agent, keyFile or passwordFile, and the machine has %s of chase.apps.ssh.agentSocket and keyFile, which it would log in with", at, credentialsSaid(c))
	}
	return c.Agent, c.KeyFile, "", c.Identity, nil
}

// TierRoutes are the tier's own machines, each an SSH route with the
// credential it logs in with, in name order: none for a tier with no SSH.
// Each is held to what a grant's machine is, and decided by the catalogue,
// the tier's answers and its own lists exactly as one is; they are in
// every session of the tier, whatever its checkout's grant says.
func (c Config) TierRoutes(name string) ([]policy.SSHRoute, error) {
	tier, ok := c.Tiers[name]
	if !ok || len(tier.Hosts) == 0 {
		return nil, nil
	}
	at := "chase.tiers." + name + ".apps.ssh"
	hosts := map[string]Host{}
	catalogues := map[string]string{}
	for n, h := range tier.Hosts {
		hosts[n] = h.Host
		catalogues[n] = h.Catalogue
	}
	routes, err := c.hostRoutes(name, at, hosts, catalogues)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		r := &routes[i]
		if r.Agent, r.KeyFile, r.PasswordFile, r.Identity, err = c.login(at+".hosts."+r.Name, tier.Hosts[r.Name]); err != nil {
			return nil, err
		}
	}
	return routes, nil
}

// clashes is a grant's machine the tier names already, by its name or its
// address: a grant adds machines to a tier's, and never says again, or
// otherwise, what the tier says of one.
func (t Tier) clashes(b Binding) error {
	if n := len(t.Hosts) + len(b.Hosts); n > maxHosts {
		return fmt.Errorf("apps.ssh.hosts: %d machines with the tier's own %d, more than the %d a session may have", n, len(t.Hosts), maxHosts)
	}
	addrs := map[string]string{}
	for _, n := range slices.Sorted(maps.Keys(t.Hosts)) {
		if ap, err := checkAddress(t.Hosts[n].Address); err == nil {
			addrs[ap.String()] = n
		}
	}
	for _, n := range slices.Sorted(maps.Keys(b.Hosts)) {
		if _, ok := t.Hosts[n]; ok {
			return fmt.Errorf("apps.ssh.hosts.%s is the tier's own machine: a grant adds machines, and never names one of the tier's again", n)
		}
		if ap, err := checkAddress(b.Hosts[n].Address); err == nil {
			if other, ok := addrs[ap.String()]; ok {
				return fmt.Errorf("apps.ssh.hosts.%s.address: %s is the tier's own %s", n, ap, other)
			}
		}
	}
	return nil
}

// Check is what a launch would refuse of the machine's own SSH, asked when
// the system is built (apps/ssh.nix's system.checks) rather than by the
// first session of a tier that does not start: the Linux catalogue and
// every one chase.apps.ssh.catalogues offers, whether or not a machine
// names it yet, and every tier's own machines, made as TierRoutes makes
// them and answering each command of their expect as it says. A grant's
// machines are a project's, held to the same when it is approved.
func (c Config) Check() error {
	loaded := map[string][]Operation{}
	if _, err := c.catalogue("", loaded); err != nil {
		return fmt.Errorf("catalogue: %w", err)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Catalogues)) {
		if !idPattern.MatchString(name) {
			return fmt.Errorf("chase.apps.ssh.catalogues: %q is not kebab-case, as a machine's catalogue names one", name)
		}
		if _, err := c.catalogue(name, loaded); err != nil {
			return fmt.Errorf("chase.apps.ssh.catalogues.%s: %w", name, err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Tiers)) {
		routes, err := c.TierRoutes(name)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if err := expected(r, "chase.tiers."+name+".apps.ssh.hosts."+r.Name+".expect", c.Tiers[name].Hosts[r.Name].Expect); err != nil {
				return err
			}
		}
	}
	return nil
}

// expected is each command of expect that route r, which at names, answers
// otherwise than it says, all of them together: what an edit changed is
// seen whole.
func expected(r policy.SSHRoute, at string, expect map[string]string) error {
	if len(expect) == 0 {
		return nil
	}
	rules, err := execrule.Compile(r)
	if err != nil {
		return fmt.Errorf("%s: %v", at, err)
	}
	var wrong []string
	for _, command := range slices.Sorted(maps.Keys(expect)) {
		want := expect[command]
		if !slices.Contains(answers, want) {
			return fmt.Errorf("%s: %q expects %q, not one of %s", at, command, want, strings.Join(answers, ", "))
		}
		if got := rules.Decide(command).Outcome.String(); got != want {
			wrong = append(wrong, fmt.Sprintf("%q is answered %s, not %s", command, got, want))
		}
	}
	if len(wrong) > 0 {
		return fmt.Errorf("%s: %s", at, strings.Join(wrong, "; "))
	}
	return nil
}
