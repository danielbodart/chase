package grant

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

// THE LEGACY GRANT, chase.jsonc, is read for one release beside chase.json:
// a checkout with only a chase.jsonc is approved as it always was, by
// chase.approver against what was last approved for it, and then applied
// as the chase.json it migrates to (V2), so that a launch has one way to
// apply a project's file. `chase migrate` writes that chase.json, says the
// comments it could not carry, removes chase.jsonc and signs the new file.
// hujson goes with this file, the release after.

// V2 is the legacy grant f as a chase.json says it, less what a launch
// derives -- the digest of its sops file and its Docker project -- which
// the caller adds:
//
//   - an app's allow, ask and refuse lists are its frisket route's
//     operations, an endpoint "METHOD[,METHOD] /path", and git's push the
//     operation git-receive-pack, as it was;
//   - network.allow is frisket's allow, "*.suffix" written "**.suffix",
//     and network.lan its lan, each name on the allowlist too, as a
//     launch put it there;
//   - seccomp's calls are flong's seccomp.syscalls, a call in deny denied
//     whatever allow said, and its @groups stay in its allow and deny lists;
//   - what each app binds -- a credential, Cloudflare's account, Docker's
//     images and ports, Google's APIs and account, the devShell, SSH's
//     machines -- is chase's own section's, its lists maps.
//
// One name in two of an app's lists says two things, and is refused, as
// approving one always was.
func (f File) V2() (map[string]any, error) {
	doc := map[string]any{"version": 2}
	frisket := map[string]any{}
	routes := map[string]any{}
	for _, a := range []struct {
		app string
		l   Lists
	}{
		{"cloudflare", listsOf2(f.Apps.Cloudflare, func(c *Cloudflare) Lists { return Lists{c.Allow, c.Ask, c.Refuse} })},
		{"gcloud", listsOf2(f.Apps.Gcloud, func(g *Gcloud) Lists { return Lists{g.Allow, g.Ask, g.Refuse} })},
		{"git", listsOf2(f.Apps.Git, func(l *Lists) Lists { return *l })},
		{"github", listsOf2(f.Apps.Github, func(l *Lists) Lists { return *l })},
		{"huggingface", listsOf2(f.Apps.Huggingface, func(l *Lists) Lists { return *l })},
	} {
		ops := map[string]any{}
		for _, verb := range []struct {
			answer string
			names  []Named
		}{{"allow", a.l.Allow}, {"ask", a.l.Ask}, {"refuse", a.l.Refuse}} {
			for _, n := range verb.names {
				k := n.Name
				if n.Methods != nil || n.Path != "" {
					k = strings.Join(n.Methods, ",") + " " + n.Path
				}
				if was, ok := ops[k]; ok {
					return nil, fmt.Errorf("apps.%s: %s is in %s and %s", a.app, k, was, verb.answer)
				}
				ops[k] = verb.answer
			}
		}
		if len(ops) > 0 {
			routes[a.app] = map[string]any{"operations": ops}
		}
	}
	if len(routes) > 0 {
		frisket["routes"] = routes
	}
	if n := f.Network; n != nil {
		allow := map[string]any{}
		for _, name := range n.Allow {
			if under, ok := strings.CutPrefix(name, "*."); ok {
				name = "**." + under
			}
			allow[name] = true
		}
		lan := map[string]any{}
		for _, h := range n.LAN {
			entry := map[string]any{}
			if len(h.Ports) > 0 {
				ports := make([]any, len(h.Ports))
				for i, p := range h.Ports {
					ports[i] = p
				}
				entry["ports"] = ports
			}
			lan[h.Name] = entry
			allow[h.Name] = true
		}
		if len(allow) > 0 {
			frisket["allow"] = allow
		}
		if len(lan) > 0 {
			frisket["lan"] = lan
		}
	}
	if len(frisket) > 0 {
		doc["frisket"] = frisket
	}

	if s := f.Seccomp; s != nil {
		seccomp := map[string]any{}
		calls := map[string]any{}
		var allowGroups, denyGroups []any
		for _, n := range s.Allow {
			if strings.HasPrefix(n, "@") {
				allowGroups = append(allowGroups, n)
			} else {
				calls[n] = "allow"
			}
		}
		for _, n := range s.Deny {
			if strings.HasPrefix(n, "@") {
				denyGroups = append(denyGroups, n)
			} else {
				calls[n] = "deny"
			}
		}
		if len(allowGroups) > 0 {
			seccomp["allow"] = uniqueAny(allowGroups)
		}
		if len(denyGroups) > 0 {
			seccomp["deny"] = uniqueAny(denyGroups)
		}
		if len(calls) > 0 {
			seccomp["syscalls"] = calls
		}
		if len(seccomp) > 0 {
			doc["flong"] = map[string]any{"seccomp": seccomp}
		}
	}

	chase := map[string]any{}
	if f.Secrets != "" {
		chase["secrets"] = f.Secrets
	}
	apps := map[string]any{}
	credential := func(c *Credential) any {
		if c == nil || c.Secret == "" {
			return nil
		}
		return map[string]any{"secret": c.Secret}
	}
	if c := f.Apps.Cloudflare; c != nil {
		b := map[string]any{}
		if c.AccountID != "" {
			b["accountId"] = c.AccountID
		}
		if v := credential(c.Credential); v != nil {
			b["credential"] = v
		}
		if len(b) > 0 {
			apps["cloudflare"] = b
		}
	}
	if d := f.Apps.Docker; d != nil {
		b := map[string]any{}
		if len(d.Images) > 0 {
			images := map[string]any{}
			for _, i := range d.Images {
				images[i] = true
			}
			b["images"] = images
		}
		if len(d.Ports) > 0 {
			ports := map[string]any{}
			for _, p := range d.Ports {
				ports[strconv.Itoa(p)] = true
			}
			b["ports"] = ports
		}
		apps["docker"] = b
	}
	if g := f.Apps.Gcloud; g != nil {
		b := map[string]any{}
		if g.APIs != nil {
			apis := map[string]any{}
			for _, n := range g.APIs.Add {
				apis[n] = true
			}
			for _, n := range g.APIs.Remove {
				apis[n] = false
			}
			if len(apis) > 0 {
				b["apis"] = apis
			}
		}
		if v := credential(g.Credential); v != nil {
			b["credential"] = v
		}
		if g.ServiceAccount != "" {
			b["serviceAccount"] = g.ServiceAccount
		}
		if len(b) > 0 {
			apps["gcloud"] = b
		}
	}
	if n := f.Apps.Nix; n != nil && n.DevShell {
		apps["nix"] = map[string]any{"devShell": true}
	}
	if s := f.Apps.SSH; s != nil && len(s.Hosts) > 0 {
		var v any
		b, err := json.Marshal(s)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		apps["ssh"] = v
	}
	if len(apps) > 0 {
		chase["apps"] = apps
	}
	if len(chase) > 0 {
		doc["chase"] = chase
	}
	return doc, nil
}

func listsOf2[T any](p *T, lists func(*T) Lists) Lists {
	if p == nil {
		return Lists{}
	}
	return lists(p)
}

func uniqueAny(xs []any) []any {
	var out []any
	for _, x := range xs {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// Comments are the comments of a chase.jsonc, each as it was written, in
// the order they come: what a chase.json, which has none, cannot keep.
func Comments(b []byte) ([]string, error) {
	v, err := hujson.Parse(b)
	if err != nil {
		return nil, err
	}
	var out []string
	extra := func(e hujson.Extra) {
		for _, c := range splitComments(string(e)) {
			out = append(out, c)
		}
	}
	var walk func(v *hujson.Value)
	walk = func(v *hujson.Value) {
		extra(v.BeforeExtra)
		switch c := v.Value.(type) {
		case *hujson.Object:
			for i := range c.Members {
				m := &c.Members[i]
				walk(&m.Name)
				walk(&m.Value)
			}
			extra(c.AfterExtra)
		case *hujson.Array:
			for i := range c.Elements {
				walk(&c.Elements[i])
			}
			extra(c.AfterExtra)
		}
		extra(v.AfterExtra)
	}
	walk(&v)
	return out, nil
}

// splitComments are the comments in whitespace and comments, each trimmed:
// a // comment to its line's end, a /* */ one whole.
func splitComments(s string) []string {
	var out []string
	for {
		i := strings.IndexAny(s, "/")
		if i < 0 || i+1 >= len(s) {
			return out
		}
		s = s[i:]
		switch s[1] {
		case '/':
			end := strings.IndexByte(s, '\n')
			if end < 0 {
				end = len(s)
			}
			out = append(out, strings.TrimSpace(s[:end]))
			s = s[end:]
		case '*':
			end := strings.Index(s[2:], "*/")
			if end < 0 {
				return append(out, strings.TrimSpace(s))
			}
			out = append(out, strings.TrimSpace(s[:end+4]))
			s = s[end+4:]
		default:
			s = s[1:]
		}
	}
}

// normal is a legacy grant as it is approved: a project that loosens
// nothing has no seccomp section, no network that names nothing, and says
// nothing of an app it does not bind, so a grant approved before there
// were any still is. One approved before is read through this too, so it
// is compared as it would be written now.
//
// The grant is one JSON value, and what comes back is it as jq -c wrote
// it, without the newline: its keys where they were, and its numbers as
// written. A seccomp section of exactly {allow: [], deny: []} goes, as does
// a network section with nothing left in it once pruned, and each object
// under apps loses every member that is null, [] or {} once its own have
// been pruned, so an app whose fields are all empty goes too. Arrays are
// kept as they are. A grant that is null is null; one that is not an
// object is an error, as indexing it was jq's.
func normal(grant []byte) ([]byte, error) {
	v, err := parseJSON(grant)
	if err != nil {
		return nil, err
	}
	switch v.kind {
	case '{':
		if s := v.members["seccomp"]; s != nil && unloosened(s) {
			v.del("seccomp")
		}
		// A network that adds no name adds nothing, as an app that binds
		// nothing binds nothing.
		if n := v.members["network"]; n != nil && n.kind == '{' {
			pruned(n)
			if len(n.keys) == 0 {
				v.del("network")
			}
		}
		if b := v.members["apps"]; b != nil && b.kind != 'n' && b.kind != 'f' {
			pruned(b)
		}
	case 'n':
	default:
		return nil, fmt.Errorf(`Cannot index %s with string ("seccomp")`, v.typeName())
	}
	return []byte(v.compact()), nil
}

// unloosened is whether s is {allow: [], deny: []}, and nothing else.
func unloosened(s *value) bool {
	if s.kind != '{' || len(s.keys) != 2 {
		return false
	}
	a, d := s.members["allow"], s.members["deny"]
	return a != nil && d != nil && a.kind == '[' && d.kind == '[' && len(a.items) == 0 && len(d.items) == 0
}

// pruned drops, from v and every object below it through objects, each
// member that is null, [] or {} once its own are pruned.
func pruned(v *value) {
	if v.kind != '{' {
		return
	}
	keys := v.keys[:0:0]
	for _, k := range v.keys {
		m := v.members[k]
		pruned(m)
		if emptyValue(m) {
			delete(v.members, k)
			continue
		}
		keys = append(keys, k)
	}
	v.keys = keys
}

func emptyValue(v *value) bool {
	switch v.kind {
	case 'n':
		return true
	case '{':
		return len(v.keys) == 0
	case '[':
		return len(v.items) == 0
	}
	return false
}
