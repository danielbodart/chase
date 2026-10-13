package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/danielbodart/frisket/policy"
	"github.com/danielbodart/quoin/hostpattern"
	"github.com/danielbodart/quoin/projpolicy"
	"github.com/danielbodart/quoin/sudo"

	appsssh "github.com/danielbodart/chase/internal/apps/ssh"
)

// A PROJECT'S FILE is chase.json at the checkout's root: strict JSON, one
// section per component, each that component's own shape, and signed
// beside it as chase.json.sig, a stock SSHSIG over its exact bytes in the
// namespace quoin-policy:<root> (quoin's docs/policy.md). A file whose
// signature verifies against /etc/quoin/allowed_signers is launched with
// no dialog; one that does not is put to the signer, which shows the
// change and signs it (sign.go).
//
//	{
//	  "chase": {
//	    "apps": {"docker": {"images": {"postgres:18": true}, "ports": {"5432": true}, "project": "owner/repo"}},
//	    "secrets": "secrets.yaml",
//	    "secretsSHA256": "…"
//	  },
//	  "flong": {"seccomp": {"syscalls": {"io_uring_setup": "allow"}}},
//	  "frisket": {"allow": {"pypi.org": true}, "routes": {"github": {"operations": {"pulls/create": "allow"}}}},
//	  "signer": {"ssh": {"hosts": {"gateway": "allow"}}},
//	  "version": 2
//	}
//
// Every section is optional, and each is a layer of what its component
// reads: frisket's merged over the tier's policy document with RFC 7396's
// merge patch, after frisket's own project-layer check; flong's seccomp
// turned into the lines a project's seccompPolicy prints; the signer's read
// by the signer itself; the sudo gate's kept for it. chase's own section
// holds only what no component owns: the secrets file and its digest, and
// the apps a project binds -- a credential, the Docker project, its images
// and ports, Google's APIs, the devShell, SSH machines -- which chase turns
// into routes at launch (the apps' sugar).
//
// The legacy chase.jsonc (file.go) is read for one release beside it.
const (
	FileName   = "chase.json"
	SigName    = FileName + projpolicy.SigSuffix
	LegacyName = "chase.jsonc"
)

// Doc is a chase.json, decoded. Frisket and Signer are layers merged over
// another document, so they are kept as JSON values, nulls and all;
// the rest are chase's to read.
type Doc struct {
	Version int            `json:"version"`
	Frisket map[string]any `json:"frisket,omitempty"`
	Flong   *FlongLayer    `json:"flong,omitempty"`
	Signer  map[string]any `json:"signer,omitempty"`
	Sudo    *SudoLayer     `json:"sudo,omitempty"`
	Chase   *Section       `json:"chase,omitempty"`
}

// FlongLayer is what of flong's declaration a project's file may say: its
// syscall filter, which chase applies as the lines flong's seccompPolicy
// reads (internal/grant's Result). Syscalls is flong's seccomp.syscalls
// map, a call by the kernel's name to "allow", "deny" or "log"; Allow and
// Deny are its lists, for systemd's @groups alone, a call by name being
// the map's.
type FlongLayer struct {
	Seccomp *FlongSeccomp `json:"seccomp,omitempty"`
}

type FlongSeccomp struct {
	Allow    []string          `json:"allow,omitempty"`
	Deny     []string          `json:"deny,omitempty"`
	Syscalls map[string]string `json:"syscalls,omitempty"`
}

// SudoLayer is the sudo gate's section, read by the gate itself for a sudo
// run in the checkout (quoin's docs/sudo.md, Rules): commands by their
// absolute path and arguments, each with whom it runs as and its answer,
// merged over the host's rules. Each rule is the gate's own type, quoin's
// sudo.Rule, read as the gate reads it, keys spelt exactly; chase is
// stricter only in wanting runAs said, where the gate reads none as root,
// so a project's file says whom it runs a command as.
type SudoLayer struct {
	Exec map[string]sudo.Rule `json:"exec,omitempty"`
}

// Section is chase's own: what no component owns.
type Section struct {
	// Secrets is the project's sops file, relative to the checkout, and
	// SecretsSHA256 the digest of the bytes signed with it: a launch
	// refuses a file whose digest is not this, so new ciphertext is signed
	// as any change is.
	Secrets       string       `json:"secrets,omitempty"`
	SecretsSHA256 string       `json:"secretsSHA256,omitempty"`
	Apps          *SectionApps `json:"apps,omitempty"`
}

// SectionApps are the apps a project binds, each made into routes at
// launch.
type SectionApps struct {
	Cloudflare *CloudflareBinding `json:"cloudflare,omitempty"`
	Docker     *DockerBinding     `json:"docker,omitempty"`
	Gcloud     *GcloudBinding     `json:"gcloud,omitempty"`
	Nix        *Nix               `json:"nix,omitempty"`
	SSH        *appsssh.Binding   `json:"ssh,omitempty"`
}

type CloudflareBinding struct {
	AccountID  string      `json:"accountId,omitempty"`
	Credential *Credential `json:"credential,omitempty"`
}

// DockerBinding is Docker: the project its containers are, which the
// launch holds to the one the checkout's origin names; and its images and
// ports, each a key to true.
type DockerBinding struct {
	Images  map[string]bool `json:"images,omitempty"`
	Ports   map[string]bool `json:"ports,omitempty"`
	Project string          `json:"project,omitempty"`
}

// GcloudBinding is Google Cloud: the project's service-account key, the
// account it must be for, and APIs by Discovery name, true to carry one
// beside the tier's and false to do without one of the tier's.
type GcloudBinding struct {
	APIs           map[string]bool `json:"apis,omitempty"`
	Credential     *Credential     `json:"credential,omitempty"`
	ServiceAccount string          `json:"serviceAccount,omitempty"`
}

// ParseDoc is b as a chase.json, checked as far as it can be without a
// tier: strict JSON, every section in its own shape, nothing a project
// may not set. What only a launch can check -- frisket's routes against
// the tier's, flong's syscalls against the architecture's, the derived
// digests against the checkout -- is checked there.
func ParseDoc(b []byte) (Doc, any, error) {
	v, err := projpolicy.Decode(b)
	if err != nil {
		return Doc{}, nil, err
	}
	top, ok := v.(map[string]any)
	if !ok {
		return Doc{}, nil, errors.New("not a JSON object")
	}
	if fmt.Sprint(top["version"]) != "2" {
		return Doc{}, nil, errors.New(`"version": 2 is a chase.json's first word: one without is no chase.json this chase reads`)
	}
	for _, s := range []string{"chase", "flong", "sudo", "version"} {
		if v, ok := top[s]; !ok {
			continue
		} else if at := nullAt(v, s); at != "" {
			return Doc{}, nil, fmt.Errorf("%s is null: only frisket's and the signer's sections are layers, whose null deletes", at)
		}
	}
	var d Doc
	if err := strict(b, &d); err != nil {
		return Doc{}, nil, err
	}
	if err := d.check(); err != nil {
		return Doc{}, nil, err
	}
	return d, v, nil
}

// nullAt is where in v a null is, or "".
func nullAt(v any, at string) string {
	switch v := v.(type) {
	case nil:
		return at
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if w := nullAt(v[k], at+"."+k); w != "" {
				return w
			}
		}
	case []any:
		for i, x := range v {
			if w := nullAt(x, fmt.Sprintf("%s[%d]", at, i)); w != "" {
				return w
			}
		}
	}
	return ""
}

func (d Doc) check() error {
	if d.Frisket != nil {
		if err := checkFrisketLayer(d.Frisket); err != nil {
			return err
		}
	}
	if d.Flong != nil {
		if err := d.Flong.check(); err != nil {
			return err
		}
	}
	if d.Signer != nil {
		if err := checkSignerLayer(d.Signer); err != nil {
			return err
		}
	}
	if d.Sudo != nil {
		if err := d.Sudo.check(); err != nil {
			return err
		}
	}
	if d.Chase != nil {
		if err := d.Chase.check(); err != nil {
			return err
		}
	}
	return nil
}

// checkFrisketLayer is what frisket's `check -layer project` refuses that
// needs no base -- a key the version 2 document has no field for, or one
// only the host may set -- and what chase refuses of a project's names
// besides: every name ("**"), a public suffix's every name, more names
// than a person reads, and a local-network name that is a pattern, a
// project's own or frisket's. The rest is frisket's, at launch, against
// the tier's document (policy.CheckProjectLayer).
func checkFrisketLayer(m map[string]any) error {
	if _, ok := m["version"]; ok {
		return errors.New("frisket.version: the file's version is its own, at the top")
	}
	// A route a project answers, it answers by name: the document's own
	// answers are every route's, Claude Code's and Codex's among them.
	for _, k := range []string{"writes", "guarded", "unmatched"} {
		if _, ok := m[k]; ok {
			return fmt.Errorf("frisket.%s: answer a route's requests under its own name, routes.<name>.%s", k, k)
		}
	}
	if errs := scoped(m, reflect.TypeFor[policy.DocumentV2](), "frisket"); len(errs) > 0 {
		return errors.Join(errs...)
	}
	if a, ok := m["allow"].(map[string]any); ok {
		if err := checkAllowKeys(a); err != nil {
			return err
		}
	}
	if l, ok := m["lan"].(map[string]any); ok {
		var hosts []policy.LANHost
		for _, k := range slices.Sorted(maps.Keys(l)) {
			if l[k] != nil {
				hosts = append(hosts, policy.LANHost{Name: k})
			}
		}
		if err := CheckLAN(hosts); err != nil {
			return fmt.Errorf("frisket.%w", err)
		}
	}
	return nil
}

// scoped is every key of v, read as t, that t has no field for or that is
// the host's alone (scope:"host"), as frisket's own layer check finds them.
func scoped(v any, t reflect.Type, at string) []error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var out []error
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return nil // frisket's decode of the merged document says what is wrong
		}
		fields := jsonFields(t)
		for _, k := range slices.Sorted(maps.Keys(m)) {
			f, ok := fields[k]
			switch {
			case !ok:
				out = append(out, fmt.Errorf("%s.%s: no such field", at, k))
			case f.Tag.Get("scope") == "host":
				out = append(out, fmt.Errorf("%s.%s: the host's alone, which a project may not set or delete", at, k))
			case m[k] != nil:
				out = append(out, scoped(m[k], f.Type, at+"."+k)...)
			}
		}
	case reflect.Map:
		if m, ok := v.(map[string]any); ok {
			for _, k := range slices.Sorted(maps.Keys(m)) {
				if m[k] != nil {
					out = append(out, scoped(m[k], t.Elem(), at+"."+k)...)
				}
			}
		}
	case reflect.Slice:
		if s, ok := v.([]any); ok {
			for i, x := range s {
				out = append(out, scoped(x, t.Elem(), fmt.Sprintf("%s[%d]", at, i))...)
			}
		}
	}
	return out
}

// jsonFields are a struct's fields by their JSON names, an embedded
// struct's among them.
func jsonFields(t reflect.Type) map[string]reflect.StructField {
	out := map[string]reflect.StructField{}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if f.Anonymous && name == "" {
			maps.Copy(out, jsonFields(f.Type))
			continue
		}
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f
	}
	return out
}

// checkAllowKeys is checkNetwork for a version 2 allowlist's keys, in
// frisket's host grammar, ** for every name.
func checkAllowKeys(a map[string]any) error {
	if len(a) > maxNetwork {
		return fmt.Errorf("frisket.allow: at most %d names, not %d", maxNetwork, len(a))
	}
	for _, k := range slices.Sorted(maps.Keys(a)) {
		if _, err := hostpattern.Compile(k); err != nil {
			return fmt.Errorf("frisket.allow: %q: %v", k, err)
		}
		under, wild := strings.CutPrefix(k, "**.")
		if !wild {
			under, wild = strings.CutPrefix(k, "*.")
		}
		switch {
		case k == "**" || k == "*":
			return fmt.Errorf("frisket.allow: %q is every name, which only a tier allows", k)
		case isAddress(k):
			return fmt.Errorf("frisket.allow: %q is an address: an allowlist holds names", k)
		case wild && publicWildcard("*."+under):
			return fmt.Errorf("frisket.allow: %q is every name under a public suffix, which only a tier allows: name the domain under it", k)
		}
	}
	return nil
}

// checkSignerLayer is what the signer reads of a project's section (its
// readSigner): ssh.hosts and sshsig, each a map of allow, ask or null, a
// host key in the signer's grammar and no namespace of its own policies.
func checkSignerLayer(m map[string]any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var s struct {
		SSH *struct {
			Hosts map[string]*string `json:"hosts"`
		} `json:"ssh"`
		SSHSig map[string]*string `json:"sshsig"`
	}
	if err := strict(b, &s); err != nil {
		return fmt.Errorf("signer: %w (a project's signer section sets ssh.hosts and sshsig)", err)
	}
	rule := func(at string, r *string) error {
		if r != nil && *r != "allow" && *r != "ask" {
			return fmt.Errorf("signer.%s: %q is not allow or ask", at, *r)
		}
		return nil
	}
	if s.SSH != nil {
		for _, k := range slices.Sorted(maps.Keys(s.SSH.Hosts)) {
			if _, err := hostpattern.Compile(k); err != nil {
				return fmt.Errorf("signer.ssh.hosts: %q: %v", k, err)
			}
			if err := rule("ssh.hosts."+k, s.SSH.Hosts[k]); err != nil {
				return err
			}
		}
	}
	for _, ns := range slices.Sorted(maps.Keys(s.SSHSig)) {
		if ns == "" || strings.HasPrefix(ns, projpolicy.NamespacePrefix) {
			return fmt.Errorf("signer.sshsig: %q is not a namespace a rule may name", ns)
		}
		if err := rule("sshsig."+ns, s.SSHSig[ns]); err != nil {
			return err
		}
	}
	return nil
}

var (
	callName  = regexp.MustCompile(`^[a-z0-9_]+$`)
	groupName = regexp.MustCompile(`^@[a-z0-9_-]+$`)
)

func (f FlongLayer) check() error {
	s := f.Seccomp
	if s == nil {
		return nil
	}
	for _, l := range []struct {
		field string
		names []string
	}{{"allow", s.Allow}, {"deny", s.Deny}} {
		seen := map[string]bool{}
		for _, n := range l.names {
			switch {
			case callName.MatchString(n):
				return fmt.Errorf("flong.seccomp.%s: %q is a call, which seccomp.syscalls names: {%q: %q}", l.field, n, n, l.field)
			case !groupName.MatchString(n):
				return fmt.Errorf("flong.seccomp.%s: %q is not a systemd @group", l.field, n)
			case seen[n]:
				return fmt.Errorf("flong.seccomp.%s: %q is named twice", l.field, n)
			}
			seen[n] = true
		}
	}
	for _, n := range slices.Sorted(maps.Keys(s.Syscalls)) {
		if !callName.MatchString(n) {
			return fmt.Errorf("flong.seccomp.syscalls: %q is not a call's name: a @group is the allow and deny lists'", n)
		}
		if a := s.Syscalls[n]; a != "allow" && a != "deny" && a != "log" {
			return fmt.Errorf("flong.seccomp.syscalls.%s: %q is not allow, deny or log", n, a)
		}
	}
	return nil
}

// Lines are the seccompPolicy lines the layer makes: what it allows, its
// groups and then its calls, and what it denies and logs. A project's deny
// wins over its own allow in flong's reading of these lines, so a call
// the map allows that one of the layer's own denied groups holds stays
// denied.
func (f *FlongLayer) Lines() Result {
	var r Result
	if f == nil || f.Seccomp == nil {
		return r
	}
	s := f.Seccomp
	r.Allow = slices.Clone(s.Allow)
	r.Deny = slices.Clone(s.Deny)
	for _, n := range slices.Sorted(maps.Keys(s.Syscalls)) {
		switch s.Syscalls[n] {
		case "allow":
			r.Allow = append(r.Allow, n)
		case "deny":
			r.Deny = append(r.Deny, n)
		case "log":
			r.Log = append(r.Log, n)
		}
	}
	return r
}

func (s SudoLayer) check() error {
	// chase's one rule of its own: a rule says whom it runs as, which the
	// gate would read as root when absent. Everything else -- a command by
	// its absolute, clean path, runAs a user's name, the answer one of
	// three -- is the gate's own reading, quoin's sudo.CheckExec, and is
	// left to it, so that what chase refuses cannot drift from what the
	// gate reads.
	for _, k := range slices.Sorted(maps.Keys(s.Exec)) {
		if s.Exec[k].RunAs == "" {
			return fmt.Errorf("sudo.exec.%s.runAs: a project's rule says whom it runs as, root too", k)
		}
	}
	// The gate's own reading: a rule it would refuse, and so ignore the
	// whole file over, is refused here before it is signed.
	if err := sudo.CheckExec(s.Exec); err != nil {
		return fmt.Errorf("sudo.%w", err)
	}
	return nil
}

var (
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	projectSlug = regexp.MustCompile(`^[a-z0-9-]+/[a-z0-9._-]+$`)
	portKey     = regexp.MustCompile(`^[1-9][0-9]*$`)
)

func (s Section) check() error {
	if s.Secrets != "" && !secretsFile.MatchString(s.Secrets) {
		return fmt.Errorf("chase.secrets: %q is not relative to the checkout", s.Secrets)
	}
	if (s.Secrets == "") != (s.SecretsSHA256 == "") {
		return errors.New("chase.secretsSHA256 is the digest of chase.secrets, signed with it: give both or neither (chase sign writes it)")
	}
	if s.SecretsSHA256 != "" && !sha256Hex.MatchString(s.SecretsSHA256) {
		return fmt.Errorf("chase.secretsSHA256: %q is not 64 lower-case hex digits", s.SecretsSHA256)
	}
	if s.Apps == nil {
		return nil
	}
	a := s.Apps
	if c := a.Cloudflare; c != nil {
		if err := checkCredential("chase.apps.cloudflare", c.Credential); err != nil {
			return err
		}
		if c.AccountID != "" && !accountID.MatchString(c.AccountID) {
			return fmt.Errorf("chase.apps.cloudflare.accountId: %q is not 32 lower-case hex digits", c.AccountID)
		}
	}
	if d := a.Docker; d != nil {
		if d.Project != "" && !projectSlug.MatchString(d.Project) {
			return fmt.Errorf("chase.apps.docker.project: %q is not owner/repo, lower-cased", d.Project)
		}
		for _, image := range slices.Sorted(maps.Keys(d.Images)) {
			if !d.Images[image] {
				return fmt.Errorf("chase.apps.docker.images: %s is false: an image is listed with true, or not at all", image)
			}
			if why := imageProblem(image); why != "" {
				return fmt.Errorf("chase.apps.docker.images: %s %s", image, why)
			}
		}
		ports, err := d.ports()
		if err != nil {
			return err
		}
		if err := checkPorts(ports); err != nil {
			return fmt.Errorf("chase.%w", err)
		}
	}
	if g := a.Gcloud; g != nil {
		if err := checkCredential("chase.apps.gcloud", g.Credential); err != nil {
			return err
		}
		if g.ServiceAccount != "" && !serviceAccount.MatchString(g.ServiceAccount) {
			return fmt.Errorf("chase.apps.gcloud.serviceAccount: %q is not an account's email", g.ServiceAccount)
		}
		for _, n := range slices.Sorted(maps.Keys(g.APIs)) {
			if !apiName.MatchString(n) {
				return fmt.Errorf("chase.apps.gcloud.apis: %q is not a Discovery name", n)
			}
		}
	}
	if b := a.SSH; b != nil {
		if err := b.Check("chase.apps.ssh"); err != nil {
			return err
		}
	}
	return nil
}

// ports are the binding's ports, as numbers, in order.
func (d DockerBinding) ports() ([]int, error) {
	var out []int
	for _, k := range slices.Sorted(maps.Keys(d.Ports)) {
		p, err := strconv.Atoi(k)
		if !portKey.MatchString(k) || err != nil {
			return nil, fmt.Errorf("chase.apps.docker.ports: %q is not a port's number", k)
		}
		if !d.Ports[k] {
			return nil, fmt.Errorf("chase.apps.docker.ports: %s is false: a port is listed with true, or not at all", k)
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

// Canonical is b as chase fmt writes it, the bytes a chase.json is signed
// over: frisket's canonical form, keys sorted, two spaces an indent, a
// newline at the end.
func Canonical(b []byte) ([]byte, error) { return projpolicy.Format(b) }

// encodeDoc is a decoded file, in the canonical form.
func encodeDoc(v any) ([]byte, error) { return projpolicy.Encode(v) }

// bindingOf is an app's binding as its code reads one: the chase
// section's, in the shape the app's Prepare was written for -- Docker's
// images and ports as lists, Google's APIs as what is added and removed.
func bindingOf(app string, raw any) (json.RawMessage, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	switch app {
	case "docker":
		var d DockerBinding
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		ports, err := d.ports()
		if err != nil {
			return nil, err
		}
		if ports == nil {
			ports = []int{}
		}
		return json.Marshal(map[string]any{"images": slices.Sorted(maps.Keys(d.Images)), "ports": ports})
	case "gcloud":
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		if apis, ok := m["apis"].(map[string]any); ok {
			add, remove := []string{}, []string{}
			for _, n := range slices.Sorted(maps.Keys(apis)) {
				if apis[n] == true {
					add = append(add, n)
				} else {
					remove = append(remove, n)
				}
			}
			m["apis"] = map[string]any{"add": add, "remove": remove}
		}
		return json.Marshal(m)
	}
	return b, nil
}

// compactJSON is v as one line of JSON, <, > and & as themselves.
func compactJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}
