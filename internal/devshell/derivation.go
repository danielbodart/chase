package devshell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// derivation is what chase reads of one in `nix derivation show`: its
// environment; its inputs -- each derivation, by its name in the store, and
// the outputs taken of it, in the format of nix 2.33 and later
// (inputs.drvs) or of those before (inputDrvs); and its structured
// attributes, where nix gives them apart.
type derivation struct {
	Env    map[string]string `json:"env"`
	Inputs struct {
		Drvs map[string]json.RawMessage `json:"drvs"`
	} `json:"inputs"`
	InputDrvs       map[string]json.RawMessage `json:"inputDrvs"`
	StructuredAttrs map[string]any             `json:"structuredAttrs"`
}

// Each is matched whole: a derivation's name in the store, and an
// output's, as nix makes them -- never a word nix would take for an
// option of its own.
var (
	drvName    = regexp.MustCompile(`^[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+\.drv$`)
	outputName = regexp.MustCompile(`^[A-Za-z0-9+_?=][A-Za-z0-9+._?=-]*$`)
)

var unread = errors.New("nix printed a derivation chase does not read")

// inputsOf is what of the derivation drv `nix derivation show` printed in
// out its inputs are, each as nix builds it, DRV^OUT,OUT -- the outputs
// the devShell takes, and never `^*`, which would be every output, a
// package's debug symbols too -- sorted; or why it is not one chase
// realises.
func inputsOf(drv string, out []byte) ([]string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, unread
	}
	raw := doc
	if d, ok := doc["derivations"]; ok {
		raw = nil
		if err := json.Unmarshal(d, &raw); err != nil {
			return nil, unread
		}
	}
	var d derivation
	found := false
	for k, v := range raw {
		if storePath(k) != drv {
			continue
		}
		if err := json.Unmarshal(v, &d); err != nil {
			return nil, unread
		}
		found = true
	}
	if !found {
		return nil, unread
	}
	if what := unsandboxed(d); what != "" {
		return nil, fmt.Errorf("the devShell asks nix for %s, which a sandboxed build is not given", what)
	}
	drvs := d.Inputs.Drvs
	if drvs == nil {
		drvs = d.InputDrvs
	}
	var inputs []string
	for k, v := range drvs {
		if !drvName.MatchString(strings.TrimPrefix(k, "/nix/store/")) {
			return nil, unread
		}
		outs, err := outputsOf(v)
		if err != nil {
			return nil, err
		}
		if len(outs) > 0 {
			inputs = append(inputs, storePath(k)+"^"+strings.Join(outs, ","))
		}
	}
	slices.Sort(inputs)
	return inputs, nil
}

// storePath is a derivation's path as nix printed it: whole before 2.33,
// its name in the store since.
func storePath(k string) string {
	if strings.HasPrefix(k, "/") {
		return k
	}
	return "/nix/store/" + k
}

// outputsOf is an input's outputs, sorted: {"outputs": [...]} or, before,
// the list. One that takes outputs of a derivation another builds --
// dynamicOutputs -- is one chase cannot substitute ahead of it.
func outputsOf(v json.RawMessage) ([]string, error) {
	var outs []string
	if t := bytes.TrimSpace(v); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(t, &outs); err != nil {
			return nil, unread
		}
	} else {
		var o struct {
			Outputs        []string                   `json:"outputs"`
			DynamicOutputs map[string]json.RawMessage `json:"dynamicOutputs"`
		}
		if err := json.Unmarshal(v, &o); err != nil {
			return nil, unread
		}
		if len(o.DynamicOutputs) > 0 {
			return nil, errors.New("the devShell takes the outputs of a derivation another derivation makes, which nothing substitutes")
		}
		outs = o.Outputs
	}
	for _, o := range outs {
		if !outputName.MatchString(o) {
			return nil, unread
		}
	}
	slices.Sort(outs)
	return outs, nil
}

// unsandboxed is what d asks to be built with that the daemon's sandbox
// does not give, "" for nothing: __noChroot, __impure, or the system
// features recursive-nix and uid-range, in its environment or its
// structured attributes. nix's record of a devShell's environment is a
// derivation of the devShell's own attributes, built here, so what one
// asks for, it asks for.
func unsandboxed(d derivation) string {
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
			return k
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
	for _, f := range []string{"recursive-nix", "uid-range"} {
		if slices.Contains(features, f) {
			return "the system feature " + f
		}
	}
	return ""
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
