package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/danielbodart/frisket/docker"
	"github.com/danielbodart/frisket/policy"

	"github.com/danielbodart/chase/internal/projectaddr"
)

// Nix is what a project's sessions are given of Nix (internal/devshell).
type Nix struct {
	// DevShell turns the checkout's devShell -- flake.nix's
	// devShells.<system>.default, or shell.nix's -- on, in any tier with
	// nix: none is evaluated without it, as with `direnv allow`. Realised
	// with the host's network where the tier's egress is direct and
	// unfiltered, and with none in any other; a launch is refused where it
	// cannot be.
	//
	// The files are not approved with it: once a grant has turned it on, a
	// devShell is what the checkout's flake.nix or shell.nix says at each
	// launch, what it may reach standing in for an approval (PLAN.md,
	// decision 21).
	DevShell bool `json:"devShell,omitempty"`
}

// Credential names the key in the grant's sops file holding an app's
// credential. Decrypted at launch outside the session, and put on the wire
// by frisket; the session holds a placeholder.
type Credential struct {
	Secret string `json:"secret,omitempty"`
}

// strict is json.Unmarshal, refusing a member v does not name and anything
// after the one value, and matching every member's name exactly, case
// included. encoding/json alone takes "Signer" or "SUDO" for a field,
// but the programs that read a project's file -- the signer, the sudo
// gate, frisket -- look a section up by its exact key, so a file chase
// read that way would have it check a section nobody applies.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("more than one value")
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	return exactKeys(raw, reflect.TypeOf(v), "")
}

var unmarshaler = reflect.TypeFor[json.Unmarshaler]()

// exactKeys is the first member of v, read as t, whose name is a field's
// only in another case. A type that reads itself (json.Unmarshaler) says
// for itself which keys it takes, as quoin's sudo.Rule does, exactly.
func exactKeys(v any, t reflect.Type, at string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Implements(unmarshaler) || reflect.PointerTo(t).Implements(unmarshaler) {
		return nil
	}
	join := func(k string) string {
		if at == "" {
			return k
		}
		return at + "." + k
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		fields := jsonFields(t)
		for _, k := range slices.Sorted(maps.Keys(m)) {
			f, ok := fields[k]
			if !ok {
				for name := range fields {
					if strings.EqualFold(name, k) {
						return fmt.Errorf("%s: no such key, though %q is: keys are matched exactly, case included", join(k), join(name))
					}
				}
				return fmt.Errorf("%s: no such key", join(k))
			}
			if m[k] != nil {
				if err := exactKeys(m[k], f.Type, join(k)); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		if m, ok := v.(map[string]any); ok {
			for _, k := range slices.Sorted(maps.Keys(m)) {
				if m[k] != nil {
					if err := exactKeys(m[k], t.Elem(), join(k)); err != nil {
						return err
					}
				}
			}
		}
	case reflect.Slice:
		if s, ok := v.([]any); ok {
			for i, x := range s {
				if err := exactKeys(x, t.Elem(), fmt.Sprintf("%s[%d]", at, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Each is matched whole.
var (
	secretsFile    = regexp.MustCompile(`^[^/].*$`)
	secretKey      = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	apiName        = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	accountID      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	serviceAccount = regexp.MustCompile(`^[^@[:space:]]+@[^@[:space:]]+$`)
)

// maxNetwork is how many names a grant's network may add: a session's
// allowlist is read on every lookup, and a list longer than this is no
// longer one a person reads before approving it.
const maxNetwork = 256

// lanName is an exact name: lower-case labels, joined by dots, and no
// wildcard.
var lanName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// CheckLAN is what frisket holds a document's lan list to, refused here
// first, of the names a grant may give: each an exact name -- no "*",
// since a name below one is anybody's to give any address -- lower-case,
// with no trailing dot; not an address, which a name is looked up to give;
// never a project's name, nor one under frisket's own reserved names,
// which the session's DNS answers with a loopback address of the host's
// and never looks up; and each once. Ports are TCP's, 1 to 65535, each
// once; none is every port. That each is on the allowlist the launch
// makes so, and that none is a route's host it checks then, when the
// routes are known.
func CheckLAN(hosts []policy.LANHost) error {
	if len(hosts) > maxNetwork {
		return fmt.Errorf("network.lan: at most %d names, not %d", maxNetwork, len(hosts))
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		n := h.Name
		switch {
		case strings.Contains(n, "*"):
			return fmt.Errorf("network.lan: %q: an exact name, never a wildcard: a name below one is anybody's to give any address", n)
		case len(n) > 253 || !lanName.MatchString(n):
			return fmt.Errorf("network.lan: %q is not a name: lower-case letters, digits and hyphens, in labels joined by dots", n)
		case isAddress(n):
			return fmt.Errorf("network.lan: %q is an address: a host on the local network is named, and reached at the address its name gives", n)
		case projectaddr.IsName(n):
			return fmt.Errorf("network.lan: %q is a project's name, which frisket answers with the project's own loopback address", n)
		case projectaddr.Reserved(n):
			return fmt.Errorf("network.lan: %q is under a name frisket keeps for its own", n)
		case seen[n]:
			return fmt.Errorf("network.lan: %q is named twice: give it every port it needs", n)
		}
		seen[n] = true
		ports := map[int]bool{}
		for _, p := range h.Ports {
			switch {
			case p < 1 || p > 65535:
				return fmt.Errorf("network.lan: %s: port %d: 1 to 65535", n, p)
			case ports[p]:
				return fmt.Errorf("network.lan: %s: port %d is named twice", n, p)
			}
			ports[p] = true
		}
	}
	return nil
}

// publicWildcard is whether n is "*." before a public suffix, as the
// public suffix list has them, its private section's too: one anybody
// registers names under. A suffix the list does not hold is taken, as the
// list's own rule does, to be one when it is a single label: *.internal.
func publicWildcard(n string) bool {
	under, ok := strings.CutPrefix(n, "*.")
	if !ok {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(under)
	return suffix == under
}

// isAddress is whether n is an IPv4 address, which networkName would take
// for four labels of digits.
func isAddress(n string) bool {
	_, err := netip.ParseAddr(n)
	return err == nil
}

func checkCredential(at string, c *Credential) error {
	if c != nil && c.Secret != "" && !secretKey.MatchString(c.Secret) {
		return fmt.Errorf("%s.credential.secret: %q is not a key in the sops file", at, c.Secret)
	}
	return nil
}

// checkPorts is what frisket refuses of a document's ports, refused here
// first, when the grant is read.
func checkPorts(ports []int) error {
	if len(ports) > 64 {
		return fmt.Errorf("apps.docker.ports: at most 64 ports, not %d", len(ports))
	}
	seen := map[int]bool{}
	for _, p := range ports {
		switch {
		case p < 1024 || p > 65535:
			return fmt.Errorf("apps.docker.ports: %d is not a port from 1024 to 65535", p)
		case seen[p]:
			return fmt.Errorf("apps.docker.ports: %d is named twice", p)
		}
		seen[p] = true
	}
	return nil
}

// AN IMAGE as `docker pull` would be given it, in the one form that names
// it: the familiar name, a tag or a digest always, and a registry only by a
// dotted domain. frisket admits a pull or a run only of a name in the list,
// compared as a string, so a second spelling of the same image would be a
// second thing to approve: docker.io/, index.docker.io/ and library/ are the
// familiar name spelled out, and are refused.
//
// The daemon runs in the host's network and treats a loopback registry as
// insecure, so a registry judged by its spelling would let a listed image
// pull from the host's own loopback: by a name that resolves there
// (registry.localhost, localhost.localdomain, anything.nip.io, a project's
// .internal name in /etc/hosts), or by an address as inet_aton reads it
// (127.1, 0x7f.1). So a registry is one of frisket's fixed public ones,
// whose names no project controls, and nothing else: frisket's ValidImage
// says which, and refuses an image's ID, which the daemon would run
// whatever local image has; this refuses the spellings on top of it.
var imagePattern = regexp.MustCompile(`^([a-z0-9-]+(\.[a-z0-9-]+)+/)?[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[0-9a-f]{64})$`)

func imageProblem(s string) string {
	first, _, _ := strings.Cut(s, "/")
	switch {
	case !imagePattern.MatchString(s):
		return "is not a familiar name with a :tag or @sha256:<64 hex>"
	case slices.Contains([]string{"docker.io", "index.docker.io", "registry-1.docker.io", "library"}, first) && strings.Contains(s, "/"):
		return "spells out Docker Hub; name it as `docker pull` shortens it"
	case first == "localhost" && strings.Contains(s, "/"):
		return "is from a registry on the host's own loopback"
	}
	if err := docker.ValidImage(s); err != nil {
		return "is " + err.Error()
	}
	return ""
}
