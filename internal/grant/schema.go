package grant

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/policy"
)

// Schema is a chase.json's JSON Schema, draft 2020-12, made of its
// components' own: the frisket section is frisket's version 2 document's
// (policy.SchemaV2), with "x-scope": "host" on what a project may not set,
// and the rest is read off the types ParseDoc decodes each section into, so
// it names every key they do and no other.
func Schema() []byte {
	var frisket map[string]any
	if err := json.Unmarshal(policy.SchemaV2(), &frisket); err != nil {
		panic(err)
	}
	delete(frisket, "$schema")
	delete(frisket, "required")
	frisket["title"] = "frisket's section: a layer of the session's policy document, merged over the tier's"
	if props, ok := frisket["properties"].(map[string]any); ok {
		delete(props, "version")
	}
	s := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"title":                "chase.json: a project's signed file, a section per component",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"version"},
		"properties": map[string]any{
			"version": map[string]any{"const": 2},
			"frisket": frisket,
			"flong":   titled(schemaOf(reflect.TypeFor[FlongLayer]()), "flong's section: the syscall filter, applied as a project's seccompPolicy lines"),
			"signer":  titled(signerSchema(), "quoin-signer's section, which the signer reads itself"),
			"sudo":    titled(schemaOf(reflect.TypeFor[SudoLayer]()), "the sudo gate's section, kept for it"),
			"chase":   titled(schemaOf(reflect.TypeFor[Section]()), "chase's own: the secrets file and the apps a project binds"),
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return buf.Bytes()
}

func titled(s map[string]any, title string) map[string]any {
	s["title"] = title
	return s
}

var (
	answerEnum  = map[string]any{"enum": []string{"allow", "ask", "refuse"}}
	signerRule  = map[string]any{"enum": []any{"allow", "ask", nil}}
	callAnswers = map[string]any{"enum": []string{"allow", "deny", "log"}}
)

// enums are the string fields, and the maps whose values, are one of a
// few words, by Go type and field.
var enums = map[string]map[string]any{
	"FlongSeccomp.Syscalls": callAnswers,
	"Rule.Answer":           answerEnum,
	"Host.Unmatched":        answerEnum,
}

// alsoRequired are fields chase wants said that their own type, another
// program's, leaves optional: a sudo rule's runAs, which the gate reads as
// root when absent, and chase.json says explicitly.
var alsoRequired = map[string]bool{
	"Rule.RunAs": true,
}

func signerSchema() map[string]any {
	rules := map[string]any{"type": "object", "additionalProperties": signerRule}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"ssh": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties":           map[string]any{"hosts": rules},
			},
			"sshsig": rules,
		},
	}
}

func schemaOf(t reflect.Type) map[string]any {
	switch t.Kind() {
	case reflect.Pointer:
		return schemaOf(t.Elem())
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": schemaOf(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaOf(t.Elem())}
	case reflect.Struct:
		props := map[string]any{}
		var required []string
		for name, f := range jsonFields(t) {
			key := t.Name() + "." + f.Name
			p := schemaOf(f.Type)
			if e, ok := enums[key]; ok {
				if f.Type.Kind() == reflect.Map {
					p["additionalProperties"] = e
				} else {
					p = e
				}
			}
			props[name] = p
			if !strings.Contains(f.Tag.Get("json"), "omitempty") && f.Type.Kind() != reflect.Pointer || alsoRequired[key] {
				required = append(required, name)
			}
		}
		s := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		if len(required) > 0 {
			slices.Sort(required)
			s["required"] = required
		}
		return s
	}
	return map[string]any{}
}
