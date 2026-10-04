package devshell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// derivation is what chase reads of one in `nix derivation show`: its
// environment, its inputs -- each derivation, by path, and the outputs
// taken of it, in the format of nix 2.33 and later (inputs.drvs) or of
// those before (inputDrvs) -- and its structured attributes, where nix
// gives them apart.
type derivation struct {
	Env    map[string]string `json:"env"`
	Inputs struct {
		Drvs map[string]json.RawMessage `json:"drvs"`
	} `json:"inputs"`
	InputDrvs       map[string]json.RawMessage `json:"inputDrvs"`
	StructuredAttrs map[string]any             `json:"structuredAttrs"`
}

// derivationOf is the one derivation step A printed, by path, and its
// inputs as step B builds them, DRV^OUT,OUT each, sorted; or why it is
// not one chase realises.
func derivationOf(out []byte) (string, []string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		return "", nil, errors.New("nix printed a derivation chase does not read")
	}
	raw := doc
	if d, ok := doc["derivations"]; ok {
		raw = nil
		if err := json.Unmarshal(d, &raw); err != nil {
			return "", nil, errors.New("nix printed a derivation chase does not read")
		}
	} else if !all(slices.Collect(maps.Keys(doc)), func(k string) bool { return strings.HasSuffix(k, ".drv") }) {
		return "", nil, errors.New("nix printed a derivation chase does not read")
	}
	if len(raw) != 1 {
		return "", nil, fmt.Errorf("the devShell is %d derivations, not one", len(raw))
	}
	var path string
	var d derivation
	for k, v := range raw {
		path = storePath(k)
		if err := json.Unmarshal(v, &d); err != nil {
			return "", nil, errors.New("nix printed a derivation chase does not read")
		}
	}
	if unsandboxed(d) {
		return "", nil, errors.New("the devShell asks nix for what a sandboxed build is not given")
	}
	drvs := d.Inputs.Drvs
	if drvs == nil {
		drvs = d.InputDrvs
	}
	var inputs []string
	for k, v := range drvs {
		outs, err := outputsOf(v)
		if err != nil {
			return "", nil, err
		}
		if len(outs) > 0 {
			inputs = append(inputs, storePath(k)+"^"+strings.Join(outs, ","))
		}
	}
	slices.Sort(inputs)
	return path, inputs, nil
}

// storePath is a derivation's path as nix printed it: whole before 2.33,
// its name in the store since.
func storePath(k string) string {
	if strings.HasPrefix(k, "/") {
		return k
	}
	return "/nix/store/" + k
}

// outputsOf is an input's outputs: {"outputs": [...]} or, before, the list.
func outputsOf(v json.RawMessage) ([]string, error) {
	var outs []string
	if t := bytes.TrimSpace(v); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(t, &outs); err != nil {
			return nil, errors.New("nix printed a derivation chase does not read")
		}
	} else {
		var o struct {
			Outputs []string `json:"outputs"`
		}
		if err := json.Unmarshal(v, &o); err != nil {
			return nil, errors.New("nix printed a derivation chase does not read")
		}
		outs = o.Outputs
	}
	slices.Sort(outs)
	return outs, nil
}

// unsandboxed is whether d asks to be built outside the daemon's sandbox,
// or with what the sandbox is not given: __noChroot, __impure, or the
// system features recursive-nix and uid-range, in its environment or its
// structured attributes.
func unsandboxed(d derivation) bool {
	attrs := map[string]any{}
	for k, v := range d.Env {
		attrs[k] = v
	}
	if j, ok := d.Env["__json"]; ok {
		var s map[string]any
		if json.Unmarshal([]byte(j), &s) == nil {
			maps.Copy(attrs, s)
		}
	}
	maps.Copy(attrs, d.StructuredAttrs)
	for _, k := range []string{"__noChroot", "__impure"} {
		if truthy(attrs[k]) {
			return true
		}
	}
	var features []string
	switch f := attrs["requiredSystemFeatures"].(type) {
	case string:
		features = strings.Fields(f)
	case []any:
		for _, e := range f {
			if s, ok := e.(string); ok {
				features = append(features, s)
			}
		}
	}
	return slices.Contains(features, "recursive-nix") || slices.Contains(features, "uid-range")
}

// truthy is a derivation attribute as nix reads it: a boolean, or in the
// environment "1" for true and "" for false; a number, in structured
// attributes, true but for 0; anything else, true if it is there.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	}
	return v != nil
}

func all[T any](s []T, f func(T) bool) bool {
	for _, e := range s {
		if !f(e) {
			return false
		}
	}
	return true
}
