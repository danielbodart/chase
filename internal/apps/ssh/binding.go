package ssh

import (
	"bytes"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	sshkey "golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/policy"
)

// Binding is what a grant says of SSH: the machines its sessions may run
// commands on, by the name ssh knows each by in the sandbox. Each host's
// rules are its own, never the app's: a rule for one machine says nothing
// of another, and the lists every other app has at its top are operations
// of an API.
type Binding struct {
	Hosts map[string]Host `json:"hosts,omitempty"`
}

// Host is one machine, as frisket's SSH route has it, less the credential,
// which is the machine's (chase.apps.ssh): a project names where it runs
// commands and as whom, never what logs in.
type Host struct {
	// Address is a literal IP, v4:port or [v6]:port, 22 when it names no
	// port. Never a name: what is reached is fixed here, when it is
	// approved, not by whatever a resolver says later.
	Address string `json:"address,omitempty"`
	// Allow, Ask and Refuse are what the project says of this machine's
	// commands, before the tier: operation ids from the catalogue,
	// category:<name>, or command patterns -- a pattern has a space or a
	// `*`, an id never does.
	Allow []string `json:"allow,omitempty"`
	Ask   []string `json:"ask,omitempty"`
	// HostKeys are the machine's own keys, as known_hosts writes them less
	// the host: the one trust in it, never learnt on first use.
	HostKeys []string `json:"hostKeys,omitempty"`
	Refuse   []string `json:"refuse,omitempty"`
	// Shell is for a device whose login shell ignores the command an exec
	// carries -- a router's or a modem's CLI: frisket types each command
	// into that shell on a terminal instead (its docs/ssh.md, "Shell
	// routes"). Only one simple command of plain words is readable there,
	// none of its stdin is sent, and the tier's env is not taken off it.
	Shell bool `json:"shell,omitempty"`
	// Unmatched is what a command no rule matches is answered with, in
	// place of the tier's: "allow", "ask" or "refuse".
	Unmatched string `json:"unmatched,omitempty"`
	// User is who the commands run as.
	User string `json:"user,omitempty"`
}

// What frisket refuses of an SSH route on its own (its internal/sshroute),
// refused here first, before a person is asked to approve a grant frisket
// would not load. What frisket refuses of one against the rest of the
// session's document is not known until launch, and is refused there: a
// name that is an intercepted host's, or under one, or the Docker route's,
// and the Docker project's address.
var (
	hostName      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
	loginName     = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._@-]*$`)
	categoryName  = regexp.MustCompile(`^category:[a-z][a-z0-9-]*$`)
	answers       = []string{"allow", "ask", "refuse"}
	maxHostName   = 253
	maxLoginName  = 255
	maxHosts      = 32
	hostKeyFormat = "\"ssh-ed25519 AAAA... [comment]\", with no host, marker or option before it"
)

// Check is what a grant may say of SSH. at is where the binding is in the
// grant, apps.ssh, which each error names with the field.
func (b Binding) Check(at string) error {
	if len(b.Hosts) > maxHosts {
		return fmt.Errorf("%s.hosts: %d machines, more than the %d a session may have", at, len(b.Hosts), maxHosts)
	}
	addrs := map[netip.AddrPort]string{}
	for _, name := range slices.Sorted(maps.Keys(b.Hosts)) {
		h := b.Hosts[name]
		at := at + ".hosts." + name
		if err := checkHostName(name); err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}
		ap, err := checkAddress(h.Address)
		if err != nil {
			return fmt.Errorf("%s.address: %w", at, err)
		}
		if other, ok := addrs[ap]; ok {
			return fmt.Errorf("%s.address: %s is %s's too", at, ap, other)
		}
		addrs[ap] = name
		if len(h.User) > maxLoginName || !loginName.MatchString(h.User) {
			return fmt.Errorf("%s.user: %q is not a login name: at most %d bytes of letters, digits and . _ @ -, not starting with - or @", at, h.User, maxLoginName)
		}
		if err := checkHostKeys(h.HostKeys); err != nil {
			return fmt.Errorf("%s.%w", at, err)
		}
		if h.Unmatched != "" && !slices.Contains(answers, h.Unmatched) {
			return fmt.Errorf("%s.unmatched: %q is not one of %s", at, h.Unmatched, strings.Join(answers, ", "))
		}
		if err := checkLists(at, h); err != nil {
			return err
		}
	}
	return nil
}

func checkHostName(name string) error {
	if len(name) > maxHostName || !hostName.MatchString(name) {
		return fmt.Errorf("%q is not a host's name: lower-case letters, digits, dots and hyphens, starting with a letter or digit", name)
	}
	// What the sandbox calls the machine, and its address is the address:
	// a name that is one would read as the other.
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("%q is an address: name the machine, and give its address as address", name)
	}
	return nil
}

// checkAddress is frisket's: a private address is what an SSH route is
// for, but not the host's own loopback, a link-local address and the
// metadata services on them, a multicast group, or the session's DNS.
func checkAddress(s string) (netip.AddrPort, error) {
	ap, err := policy.SSHRoute{Address: s}.AddrPort()
	if err != nil {
		return netip.AddrPort{}, err
	}
	a := ap.Addr()
	switch {
	case a.Zone() != "":
		return netip.AddrPort{}, fmt.Errorf("%q has a zone: a host is a machine, not an interface", s)
	case a.Is4In6():
		return netip.AddrPort{}, fmt.Errorf("%q: write an IPv4 address as IPv4", s)
	case a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return netip.AddrPort{}, fmt.Errorf("%q is not a machine's: unspecified, loopback, link-local, multicast or broadcast", s)
	case ap.Port() == 53:
		return netip.AddrPort{}, fmt.Errorf("%q: port 53 is the session's DNS", s)
	case slices.Contains(steeredAddrs, a):
		return netip.AddrPort{}, fmt.Errorf("%q is frisket's own, steered to it in every session", s)
	}
	return ap, nil
}

// steeredAddrs are frisket's service and dummy addresses, which its store
// (steeredAddrs) keeps every SSH route clear of whatever the session.
var steeredAddrs = []netip.Addr{
	netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"),
	netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2"),
}

// checkHostKeys is frisket's reading of a route's pinned keys: one or more,
// each a key alone of a type frisket asks for, none a certificate, none
// twice.
func checkHostKeys(lines []string) error {
	if len(lines) == 0 {
		return fmt.Errorf("hostKeys: none: the machine's own key is the only trust in it, and none is ever learnt on first use")
	}
	var keys [][]byte
	for i, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return fmt.Errorf("hostKeys[%d]: one key, on one line", i)
		}
		k, _, options, rest, err := sshkey.ParseAuthorizedKey([]byte(l))
		switch {
		case err != nil:
			return fmt.Errorf("hostKeys[%d]: not a key as known_hosts writes one, %s", i, hostKeyFormat)
		case len(options) > 0 || len(bytes.TrimSpace(rest)) > 0:
			return fmt.Errorf("hostKeys[%d]: %s", i, hostKeyFormat)
		}
		if _, ok := k.(*sshkey.Certificate); ok {
			return fmt.Errorf("hostKeys[%d] is a certificate: pin the machine's key itself", i)
		}
		switch k.Type() {
		case sshkey.KeyAlgoED25519, sshkey.KeyAlgoECDSA256, sshkey.KeyAlgoECDSA384, sshkey.KeyAlgoECDSA521, sshkey.KeyAlgoRSA:
		default:
			return fmt.Errorf("hostKeys[%d]: %s is not a key type frisket asks for: ed25519, ECDSA or RSA", i, k.Type())
		}
		m := k.Marshal()
		if slices.ContainsFunc(keys, func(o []byte) bool { return bytes.Equal(o, m) }) {
			return fmt.Errorf("hostKeys[%d] is listed twice", i)
		}
		keys = append(keys, m)
	}
	return nil
}

// checkLists holds each entry to the shape of what it names, and each to
// one list, once: two answers for one name would leave which one holds to
// the order a reader never sees.
func checkLists(at string, h Host) error {
	seen := map[string]string{}
	for _, l := range []struct {
		field string
		names []string
	}{{"allow", h.Allow}, {"ask", h.Ask}, {"refuse", h.Refuse}} {
		for _, n := range l.names {
			if err := checkEntry(n); err != nil {
				return fmt.Errorf("%s.%s: %w", at, l.field, err)
			}
			if other, ok := seen[n]; ok {
				if other == l.field {
					return fmt.Errorf("%s.%s: %q is listed twice", at, l.field, n)
				}
				return fmt.Errorf("%s.%s: %q is in %s too", at, l.field, n, other)
			}
			seen[n] = l.field
		}
	}
	return nil
}

// An entry is a category, an operation's id, or a command pattern, which
// alone has a space or a `*`.
type entryKind int

const (
	categoryEntry entryKind = iota
	idEntry
	patternEntry
)

func kindOf(n string) entryKind {
	switch {
	case strings.HasPrefix(n, "category:"):
		return categoryEntry
	case strings.ContainsAny(n, " *"):
		return patternEntry
	}
	return idEntry
}

func checkEntry(n string) error {
	switch kindOf(n) {
	case categoryEntry:
		if !categoryName.MatchString(n) {
			return fmt.Errorf("%q is not category:<name>", n)
		}
	case idEntry:
		if !idPattern.MatchString(n) {
			return fmt.Errorf("%q is not an operation's id; a command pattern has a space or a *, as %q does", n, n+" **")
		}
	case patternEntry:
		return CheckPattern(n)
	}
	return nil
}
