package config_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/config"
)

// file is a config with one sandbox tier whose apps.nix is nix, as the
// module writes it, with change made to it first.
func file(t *testing.T, change func(nix map[string]any)) string {
	t.Helper()
	nix := map[string]any{
		"git": "/nix/store/git/bin/git", "timeout": 1200,
		"nix": "/nix/store/nix/bin/nix", "nixpkgs": "/nix/store/nixpkgs", "system": "x86_64-linux",
		"bwrap": "/nix/store/bubblewrap/bin/bwrap", "caBundle": "/etc/ssl/certs/ca-certificates.crt",
	}
	change(nix)
	doc := map[string]any{
		"selector": map[string]any{"git": "/nix/store/git/bin/git", "fallback": "own", "tiers": map[string]any{"own": map[string]any{"launcher": "/nix/store/flong/bin/flong.chase-own"}}},
		"session":  map[string]any{"home": "/home/alice", "runtime": "/run/user/1000", "placeholder": "p", "tiers": map[string]any{"own": map[string]any{"nix": nix}}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A tool chase runs to realise a devShell, or what it is given, named
// without a slash would be looked up on the caller's PATH or read from the
// working directory: refused when the file is read, naming it.
func TestLoadRefusesARelativeNixNixpkgsBwrapOrCABundle(t *testing.T) {
	if _, err := config.Load(file(t, func(map[string]any) {})); err != nil {
		t.Fatalf("the module's own was refused: %v", err)
	}
	for _, key := range []string{"nix", "nixpkgs", "bwrap", "caBundle", "git"} {
		_, err := config.Load(file(t, func(n map[string]any) { n[key] = "relative/" + key }))
		if err == nil || !strings.Contains(err.Error(), "nix."+key+` is "relative/`+key+`", which is not an absolute path`) {
			t.Errorf("a relative %s: %v", key, err)
		}
	}
}

// No time at all, no system, and a setting chase does not know are each
// one that would not apply as written.
func TestLoadRefusesNoTimeoutNoSystemOrAnUnknownSetting(t *testing.T) {
	for _, c := range []struct {
		key  string
		v    any
		said string
	}{
		{"timeout", 0, "nix.timeout is 0"},
		{"system", "", "nix.system is empty"},
		{"devShell", "automatic", `unknown field "devShell"`},
	} {
		_, err := config.Load(file(t, func(n map[string]any) { n[c.key] = c.v }))
		if err == nil || !strings.Contains(err.Error(), c.said) {
			t.Errorf("%s = %v: %v", c.key, c.v, err)
		}
	}
}

// The schema names the keys Load decodes, at every depth, and requires
// exactly those the file always has: a field the decoder would refuse, or
// one it reads that the schema does not describe, fails here.
func TestTheSchemaMatchesTheConfig(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal([]byte(config.Schema), &root); err != nil {
		t.Fatal(err)
	}
	if root["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema is %v", root["$schema"])
	}
	defs, _ := root["$defs"].(map[string]any)
	resolve := func(s map[string]any) map[string]any {
		for {
			ref, ok := s["$ref"].(string)
			if !ok {
				return s
			}
			s, _ = defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		}
	}
	var walk func(at string, typ reflect.Type, s map[string]any)
	walk = func(at string, typ reflect.Type, s map[string]any) {
		if s == nil {
			t.Errorf("%s: no schema", at)
			return
		}
		s = resolve(s)
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		// What frisket reads, and a value kept as it was written, are
		// not this file's to describe.
		if typ == reflect.TypeFor[json.RawMessage]() || !strings.HasPrefix(typ.PkgPath(), "github.com/danielbodart/chase/") && typ.Kind() == reflect.Struct {
			return
		}
		switch typ.Kind() {
		case reflect.Map:
			item, _ := s["additionalProperties"].(map[string]any)
			walk(at+".*", typ.Elem(), item)
		case reflect.Slice:
			item, _ := s["items"].(map[string]any)
			walk(at+"[]", typ.Elem(), item)
		case reflect.Struct:
			if s["additionalProperties"] != false {
				t.Errorf("%s: the schema allows keys the decoder refuses", at)
			}
			props, _ := s["properties"].(map[string]any)
			fields := jsonFields(typ)
			var required []string
			for name, f := range fields {
				if !strings.Contains(f.Tag.Get("json"), ",omit") {
					required = append(required, name)
				}
				walk(at+"."+name, f.Type, mapOf(props[name]))
			}
			for name := range props {
				if _, ok := fields[name]; !ok {
					t.Errorf("%s: the schema has %s, which the decoder refuses", at, name)
				}
			}
			var said []string
			req, _ := s["required"].([]any)
			for _, r := range req {
				said = append(said, r.(string))
			}
			slices.Sort(required)
			slices.Sort(said)
			if !slices.Equal(required, said) {
				t.Errorf("%s: the schema requires %v, the config always has %v", at, said, required)
			}
		}
	}
	walk("config", reflect.TypeFor[config.Config](), root)
}

func mapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }

// jsonFields are typ's fields by the key each is decoded from, an embedded
// struct's own among them.
func jsonFields(typ reflect.Type) map[string]reflect.StructField {
	out := map[string]reflect.StructField{}
	for f := range typ.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if f.Anonymous && name == "" {
			maps.Copy(out, jsonFields(f.Type))
			continue
		}
		if f.IsExported() && name != "-" {
			out[name] = f
		}
	}
	return out
}

// write is a config with one sandbox tier, own, holding each enum the file
// has, with change made to it first.
func write(t *testing.T, change func(doc map[string]any)) string {
	t.Helper()
	answers := func() map[string]any { return map[string]any{"writes": "ask", "guarded": "refuse", "unmatched": "ask"} }
	doc := map[string]any{
		"selector": map[string]any{"git": "/nix/store/git/bin/git", "fallback": "own", "tiers": map[string]any{"own": map[string]any{"launcher": "/nix/store/flong/bin/flong.chase-own"}}},
		"session": map[string]any{"home": "/home/alice", "runtime": "/run/user/1000", "placeholder": "p", "tiers": map[string]any{"own": map[string]any{
			"claude": map[string]any{"scope": "workspace", "settings": "/s"},
			"codex":  map[string]any{"scope": "tier", "placeholder": "/p"},
			"stores": map[string]any{"caches": map[string]any{"scope": "tier", "root": "/home/alice/.cache/chase/caches"}},
		}}},
		"grant": map[string]any{
			"git": "/nix/store/git/bin/git", "uid": 1000, "home": "/home/alice", "policies": "/etc/frisket/policies",
			"sops": "/nix/store/sops/bin/sops", "diff": "/nix/store/diff/bin/diff",
			"gcloud": map[string]any{"tiers": map[string]any{"own": answers()}, "catalogue": "/c"},
			"ssh": map[string]any{"tiers": map[string]any{"own": func() map[string]any {
				a := answers()
				a["hosts"] = map[string]any{"box": map[string]any{"unmatched": "refuse", "expect": map[string]any{"ls": "allow"}}}
				return a
			}()}, "catalogue": "/c"},
		},
	}
	change(doc)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func at(doc map[string]any, path ...string) map[string]any {
	for _, k := range path {
		doc = doc[k].(map[string]any)
	}
	return doc
}

// A word an enum does not have would be read as some other setting, or as
// none: refused when the file is read, naming where it is.
func TestLoadRefusesAWordAnEnumDoesNotHave(t *testing.T) {
	if _, err := config.Load(write(t, func(map[string]any) {})); err != nil {
		t.Fatalf("every enum's own word was refused: %v", err)
	}
	for _, c := range []struct {
		path []string
		key  string
		said string
	}{
		{[]string{"session", "tiers", "own", "claude"}, "scope", `session: tiers.own.claude.scope is "wrong"`},
		{[]string{"session", "tiers", "own", "codex"}, "scope", `session: tiers.own.codex.scope is "wrong"`},
		{[]string{"session", "tiers", "own", "stores", "caches"}, "scope", `session: tiers.own.stores.caches.scope is "wrong"`},
		{[]string{"grant", "gcloud", "tiers", "own"}, "writes", `grant: gcloud: tiers.own.writes is "wrong"`},
		{[]string{"grant", "gcloud", "tiers", "own"}, "unmatched", `grant: gcloud: tiers.own.unmatched is "wrong"`},
		{[]string{"grant", "ssh", "tiers", "own"}, "guarded", `grant: ssh: tiers.own.guarded is "wrong"`},
		{[]string{"grant", "ssh", "tiers", "own", "hosts", "box"}, "unmatched", `grant: ssh: tiers.own.hosts.box.unmatched is "wrong"`},
		{[]string{"grant", "ssh", "tiers", "own", "hosts", "box", "expect"}, "ls", `grant: ssh: tiers.own.hosts.box.expect: "ls" expects "wrong"`},
	} {
		_, err := config.Load(write(t, func(doc map[string]any) { at(doc, c.path...)[c.key] = "wrong" }))
		if err == nil || !strings.Contains(err.Error(), c.said) {
			t.Errorf("%s.%s: %v", strings.Join(c.path, "."), c.key, err)
		}
	}
}

// A key misspelt at any depth, or a second document after the first, is a
// setting that would silently not apply.
func TestLoadRefusesAnUnknownKeyAtAnyDepthOrASecondValue(t *testing.T) {
	for _, path := range [][]string{
		{}, {"selector"}, {"session", "tiers", "own"}, {"session", "tiers", "own", "stores", "caches"},
		{"grant"}, {"grant", "gcloud", "tiers", "own"}, {"grant", "ssh", "tiers", "own", "hosts", "box"},
	} {
		_, err := config.Load(write(t, func(doc map[string]any) { at(doc, path...)["misspelt"] = true }))
		if err == nil || !strings.Contains(err.Error(), `unknown field "misspelt"`) {
			t.Errorf("misspelt in %v: %v", path, err)
		}
	}
	p := write(t, func(map[string]any) {})
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(" {}")
	f.Close()
	if _, err := config.Load(p); err == nil || !strings.Contains(err.Error(), "more than one JSON value") {
		t.Errorf("a second value: %v", err)
	}
}
