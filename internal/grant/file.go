package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/danielbodart/frisket/docker"
)

// FileName is the grant's file, at the checkout's root.
const FileName = "chase.jsonc"

// WHAT A GRANT MAY SAY (PLAN.md, decisions 10 and 17). The checkout's
// chase.jsonc is data: JSON with comments and trailing commas, read, never
// run. It is decoded into File, which refuses a member it does not name,
// and each value is checked against what that field may hold, so a
// misspelt key or a bad value refuses the launch rather than quietly
// applying nothing. What it decodes to, written again, is what a person
// approves: the comments are the project's, for its readers, and never
// reach the dialog.
//
//	{
//	  "secrets": "secrets.yaml",
//	  "bindings": {
//	    "cloudflare": {
//	      "credential": { "secret": "cloudflare-token" },
//	      "accountId": "023e105f4ecef8ad9ca31a8372d0c353",
//	    },
//	  },
//	  "seccomp": { "allow": ["io_uring_setup", "io_uring_enter", "io_uring_register"] },
//	}
//
// Fields are in the order they are written: bindings by name, as a person
// finds them.
type File struct {
	// Secrets is the project's sops file, relative to the checkout: one
	// file, many secrets, each under its own key, encrypted to admin keys. A
	// name and not the file, so what is approved is where the file is and
	// not whatever it happens to hold -- the ciphertext is the project's to
	// rotate, and its digest is approved beside the grant.
	Secrets string `json:"secrets,omitempty"`
	// Bindings is what each app is given for this project.
	Bindings Bindings `json:"bindings"`
	// Seccomp is syscalls, or systemd @groups, this project's sessions need
	// beyond the tier's filter (Allow), or do without (Deny, after Allow,
	// which it overrides). Each one allowed is kernel surface the session
	// gains. The fixed filters stay whatever this says: no terminal
	// injection, no audit socket, no namespaces of its own.
	Seccomp *Seccomp `json:"seccomp,omitempty"`
}

type Seccomp struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// Bindings is each app a project can bind.
type Bindings struct {
	Cloudflare  *Cloudflare `json:"cloudflare,omitempty"`
	Docker      *Docker     `json:"docker,omitempty"`
	Gcloud      *Gcloud     `json:"gcloud,omitempty"`
	Git         *Lists      `json:"git,omitempty"`
	Github      *Lists      `json:"github,omitempty"`
	Huggingface *Lists      `json:"huggingface,omitempty"`
}

// Lists is an app's lists (PLAN.md, decision 18). What a project names
// decides before what its tier says: a name before a category, and either
// before the tier's `writes`, `guarded` and `unmatched`. Ignored in an app
// that is anonymous.
//
// Allow is what the app lets through without a dialog: writes this project
// makes often enough that asking every time would only train a person to
// click through. Ask is what it puts to a person, and Refuse what it
// refuses, whatever the tier would do. One name in two lists is refused.
type Lists struct {
	Allow  []Named `json:"allow,omitempty"`
	Ask    []Named `json:"ask,omitempty"`
	Refuse []Named `json:"refuse,omitempty"`
}

// Credential names the key in the grant's sops file holding an app's
// credential. Decrypted at launch outside the session, and put on the wire
// by frisket; the session holds a placeholder.
type Credential struct {
	Secret string `json:"secret,omitempty"`
}

type Cloudflare struct {
	// AccountID is the Cloudflare account, set as CLOUDFLARE_ACCOUNT_ID in
	// the session. Not a secret -- it names the account, it does not open
	// it -- so it is written here, where it is approved.
	AccountID  string      `json:"accountId,omitempty"`
	Allow      []Named     `json:"allow,omitempty"`
	Ask        []Named     `json:"ask,omitempty"`
	Credential *Credential `json:"credential,omitempty"`
	Refuse     []Named     `json:"refuse,omitempty"`
}

// Docker is Docker, through frisket, on the host's rootless daemon. No
// lists: what a session may ask the daemon is fixed, and what the project
// names is which images, and which ports its containers publish.
type Docker struct {
	// Images are those this project's sessions may pull and run, each
	// exactly as it will be written: `postgres:18`, not
	// `docker.io/library/postgres:18`, and never without a tag or digest.
	Images []string `json:"images,omitempty"`
	// Ports are the host ports this project's containers publish, at most
	// 64, each once, published on the project's own loopback address and
	// reached from the session's 127.0.0.1 through frisket.
	Ports []int `json:"ports,omitempty"`
}

type Gcloud struct {
	Allow []Named `json:"allow,omitempty"`
	// APIs are Google APIs, by Discovery name, carried beside the tier's
	// (Add), and the tier's this project's sessions do without (Remove).
	APIs *APIs   `json:"apis,omitempty"`
	Ask  []Named `json:"ask,omitempty"`
	// Credential's secret holds the project's service-account key, the JSON
	// Google issues, as one string. Only the renewer reads it; the session
	// holds a key of the same shape that Google has never seen.
	Credential *Credential `json:"credential,omitempty"`
	Refuse     []Named     `json:"refuse,omitempty"`
	// ServiceAccount is the account the key must be for; a key naming
	// another is refused at launch.
	ServiceAccount string `json:"serviceAccount,omitempty"`
}

type APIs struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// Named is what a project names in an app's lists: an operation id from the
// API's own description, a whole category of them as "category:<name>", or
// -- for an endpoint the description does not name -- methods and an exact
// path template.
type Named struct {
	Name    string
	Methods []string
	Path    string
}

type endpoint struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

func (n *Named) UnmarshalJSON(b []byte) error {
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '"' {
		return json.Unmarshal(t, &n.Name)
	}
	var e endpoint
	if err := strict(b, &e); err != nil {
		return err
	}
	n.Methods, n.Path = e.Methods, e.Path
	return nil
}

func (n Named) MarshalJSON() ([]byte, error) {
	if n.Methods == nil && n.Path == "" {
		return json.Marshal(n.Name)
	}
	return json.Marshal(endpoint{n.Methods, n.Path})
}

// strict is json.Unmarshal, refusing a member v does not name and anything
// after the one value.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("more than one value")
	}
	return nil
}

// ParseFile is a chase.jsonc's grant, checked, as the JSON a person
// approves; or why it is refused.
func ParseFile(b []byte) ([]byte, error) {
	v, err := hujson.Parse(b)
	if err != nil {
		return nil, err
	}
	if err := unique(v.Value, ""); err != nil {
		return nil, err
	}
	v.Standardize()
	var f File
	if err := strict(v.Pack(), &f); err != nil {
		return nil, err
	}
	if err := f.check(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// unique refuses a member named twice in one object, anywhere: the decoder
// would keep the last, and a person reading the file might see the first.
func unique(v hujson.ValueTrimmed, at string) error {
	switch c := v.(type) {
	case *hujson.Object:
		seen := map[string]bool{}
		for _, m := range c.Members {
			name := m.Name.Value.(hujson.Literal).String()
			if seen[name] {
				return fmt.Errorf("%s is given twice", member(at, name))
			}
			seen[name] = true
			if err := unique(m.Value.Value, member(at, name)); err != nil {
				return err
			}
		}
	case *hujson.Array:
		for i, e := range c.Elements {
			if err := unique(e.Value, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func member(at, name string) string {
	if at == "" {
		return name
	}
	return at + "." + name
}

// Each is matched whole.
var (
	secretsFile    = regexp.MustCompile(`^[^/].*$`)
	secretKey      = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	syscallName    = regexp.MustCompile(`^@?[a-z0-9_-]+$`)
	apiName        = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	namedName      = regexp.MustCompile(`^(category:.+|[A-Za-z0-9_./:-]+)$`)
	namedPath      = regexp.MustCompile(`^/[^[:space:]]*$`)
	accountID      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	serviceAccount = regexp.MustCompile(`^[^@[:space:]]+@[^@[:space:]]+$`)
)

var methods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

func (f File) check() error {
	if f.Secrets != "" && !secretsFile.MatchString(f.Secrets) {
		return fmt.Errorf("secrets: %q is not relative to the checkout", f.Secrets)
	}
	if s := f.Seccomp; s != nil {
		for _, l := range []struct {
			field string
			names []string
		}{{"seccomp.allow", s.Allow}, {"seccomp.deny", s.Deny}} {
			field := l.field
			for _, n := range l.names {
				if !syscallName.MatchString(n) {
					return fmt.Errorf("%s: %q is not a syscall's name or an @group's", field, n)
				}
			}
		}
	}
	b := f.Bindings
	if c := b.Cloudflare; c != nil {
		if err := checkLists("bindings.cloudflare", Lists{c.Allow, c.Ask, c.Refuse}); err != nil {
			return err
		}
		if err := checkCredential("bindings.cloudflare", c.Credential); err != nil {
			return err
		}
		if c.AccountID != "" && !accountID.MatchString(c.AccountID) {
			return fmt.Errorf("bindings.cloudflare.accountId: %q is not 32 lower-case hex digits", c.AccountID)
		}
	}
	if d := b.Docker; d != nil {
		for _, image := range d.Images {
			if why := imageProblem(image); why != "" {
				return fmt.Errorf("bindings.docker.images: %s %s", image, why)
			}
		}
		if err := checkPorts(d.Ports); err != nil {
			return err
		}
	}
	if g := b.Gcloud; g != nil {
		if err := checkLists("bindings.gcloud", Lists{g.Allow, g.Ask, g.Refuse}); err != nil {
			return err
		}
		if err := checkCredential("bindings.gcloud", g.Credential); err != nil {
			return err
		}
		if g.ServiceAccount != "" && !serviceAccount.MatchString(g.ServiceAccount) {
			return fmt.Errorf("bindings.gcloud.serviceAccount: %q is not an account's email", g.ServiceAccount)
		}
		if a := g.APIs; a != nil {
			for _, l := range []struct {
				field string
				names []string
			}{{"add", a.Add}, {"remove", a.Remove}} {
				field := l.field
				for _, n := range l.names {
					if !apiName.MatchString(n) {
						return fmt.Errorf("bindings.gcloud.apis.%s: %q is not a Discovery name", field, n)
					}
				}
			}
		}
	}
	for _, a := range []struct {
		app string
		l   *Lists
	}{{"git", b.Git}, {"github", b.Github}, {"huggingface", b.Huggingface}} {
		if a.l != nil {
			if err := checkLists("bindings."+a.app, *a.l); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkCredential(at string, c *Credential) error {
	if c != nil && c.Secret != "" && !secretKey.MatchString(c.Secret) {
		return fmt.Errorf("%s.credential.secret: %q is not a key in the sops file", at, c.Secret)
	}
	return nil
}

func checkLists(at string, l Lists) error {
	for _, f := range []struct {
		field string
		list  []Named
	}{{"allow", l.Allow}, {"ask", l.Ask}, {"refuse", l.Refuse}} {
		field := f.field
		for _, n := range f.list {
			if n.Methods == nil && n.Path == "" {
				if !namedName.MatchString(n.Name) {
					return fmt.Errorf("%s.%s: %q is not an operation id or a category:<name>", at, field, n.Name)
				}
				continue
			}
			if len(n.Methods) == 0 {
				return fmt.Errorf("%s.%s: %s names no methods", at, field, n.Path)
			}
			for _, m := range n.Methods {
				if !slices.Contains(methods, m) {
					return fmt.Errorf("%s.%s: %q is not one of %s", at, field, m, strings.Join(methods, ", "))
				}
			}
			if !namedPath.MatchString(n.Path) {
				return fmt.Errorf("%s.%s: %q is not a path", at, field, n.Path)
			}
		}
	}
	return nil
}

// frisket's own steering listener, which a session's loopback sends the
// project's ports to.
const steering = 15001

// checkPorts is what frisket refuses of a document's ports, refused here
// first, when the grant is read.
func checkPorts(ports []int) error {
	if len(ports) > 64 {
		return fmt.Errorf("bindings.docker.ports: at most 64 ports, not %d", len(ports))
	}
	seen := map[int]bool{}
	for _, p := range ports {
		switch {
		case p < 1024 || p > 65535:
			return fmt.Errorf("bindings.docker.ports: %d is not a port from 1024 to 65535", p)
		case p == steering:
			return fmt.Errorf("bindings.docker.ports: %d is frisket's own steering listener", p)
		case seen[p]:
			return fmt.Errorf("bindings.docker.ports: %d is named twice", p)
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
