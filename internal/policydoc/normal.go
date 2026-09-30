package policydoc

import (
	"fmt"
	"strings"
)

// Normal is a grant as it is approved: a project that loosens nothing
// has no seccomp section, and says nothing of an app it does not bind, so an
// grant approved before there were any still is. One approved before is
// read through this too, so it is compared as it would be written now.
//
// The grant is one JSON value, and what comes back is it as jq -c wrote
// it, without the newline: its keys where they were, and its numbers as
// written. A seccomp section of exactly {allow: [], deny: []} goes, and each
// object under bindings loses every member that is null, [] or {} once its
// own have been pruned, so an app whose fields are all empty goes too.
// Arrays are kept as they are. A grant that is null is null; one that is
// not an object is an error, as indexing it was jq's.
func Normal(grant []byte) ([]byte, error) {
	v, err := parse(grant)
	if err != nil {
		return nil, err
	}
	switch v.kind {
	case '{':
		if s := v.get("seccomp"); s != nil && unloosened(s) {
			v.del("seccomp")
		}
		if b := v.get("bindings"); b != nil && b.kind != 'n' && b.kind != 'f' {
			pruned(b)
		}
	case 'n':
	default:
		return nil, fmt.Errorf(`Cannot index %s with string ("seccomp")`, v.typeName())
	}
	var b strings.Builder
	v.compact(&b)
	return []byte(b.String()), nil
}

// unloosened is whether s is {allow: [], deny: []}, and nothing else.
func unloosened(s *value) bool {
	if s.kind != '{' || len(s.keys) != 2 {
		return false
	}
	a, d := s.get("allow"), s.get("deny")
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
		if m.empty() {
			delete(v.members, k)
			continue
		}
		keys = append(keys, k)
	}
	v.keys = keys
}
