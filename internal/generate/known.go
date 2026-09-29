package generate

import (
	"fmt"
	"strings"
)

// known is known.json's text: the fields of each admitted body, as the spec
// gives them. Where one table is named by two operations, their bodies must
// be the same.
//
// For each operation admitted with a `body` table, it lists every field the
// spec gives that body -- object properties through $ref and allOf, not into
// an array's items or a map's values -- so that a pin bump shows new fields
// in its diff, and the check that compares the tables to it fails until
// each is decided.
func known(name string, root any, admit any) (string, error) {
	q := &eval{}
	fail := func(format string, args ...any) error {
		return &Failure{Name: name, Message: fmt.Sprintf(format, args...)}
	}
	jqErr := func() error { return &Failure{Name: name, Message: "jq: error: " + q.err.Error()} }

	resolve := func(v any) (any, error) {
		if !q.has(v, "$ref") {
			return v, nil
		}
		r := q.get(v, "$ref")
		path := r
		if s, ok := r.(string); ok {
			path = strings.TrimPrefix(s, "#/")
		}
		cur := root
		for _, p := range split(q.str(path), "/") {
			cur = q.get(cur, p)
		}
		if q.err != nil {
			return nil, jqErr()
		}
		if !truthy(cur) {
			return nil, fail("%s is not in the spec", interp(r))
		}
		return cur, nil
	}

	// Every path below a schema: each of its properties, and what is below
	// that, through a $ref and each part of an allOf -- so an allOf of
	// objects is their fields together, and one of scalars is a scalar, with
	// nothing below. An array is a field, and so is a map
	// (additionalProperties): their elements are not fields but values,
	// judged by the leaf that names the field.
	var fields func(v any, prefix string, seen []any, out *[]string) error
	fields = func(v any, prefix string, seen []any, out *[]string) error {
		if q.has(v, "$ref") {
			r := q.get(v, "$ref")
			if contains(seen, r) {
				return fail("%s contains itself, at %s", interp(r), prefix)
			}
			resolved, err := resolve(v)
			if err != nil {
				return err
			}
			return fields(resolved, prefix, append(append([]any{}, seen...), r), out)
		}
		if q.err != nil {
			return jqErr()
		}
		for _, e := range q.entries(alt(q.get(v, "properties"), NewObject())) {
			// `$prefix + .key`: an array of properties has numbers
			// for keys, which do not add to a string.
			key, ok := e.key.(string)
			if !ok {
				q.errorf("%s and %s cannot be added", describe(prefix), describe(e.key))
				return jqErr()
			}
			p := prefix + key
			*out = append(*out, p)
			if err := fields(e.value, p+".", seen, out); err != nil {
				return err
			}
		}
		for _, part := range q.iter(alt(q.get(v, "allOf"), []any{})) {
			if err := fields(part, prefix, seen, out); err != nil {
				return err
			}
		}
		if q.err != nil {
			return jqErr()
		}
		return nil
	}

	type body struct {
		table  any
		id     any
		fields []any
	}
	var bodies []body
	for _, item := range q.iter(q.get(root, "paths")) {
		shared := alt(q.get(item, "parameters"), []any{})
		for _, me := range q.entries(item) {
			if key, ok := me.key.(string); !ok || !methodKeys[key] {
				continue
			}
			op := me.value
			opID := q.get(op, "operationId")
			table := alt(q.get(q.get(q.at(admit, alt(opID, "")), "docker"), "body"), nil)
			if q.err != nil {
				return "", jqErr()
			}
			if table == nil {
				continue
			}
			var found []any
			for _, p := range append(append([]any{}, q.iter(shared)...), q.iter(alt(q.get(op, "parameters"), []any{}))...) {
				resolved, err := resolve(p)
				if err != nil {
					return "", err
				}
				if equal(q.get(resolved, "in"), "body") {
					found = append(found, resolved)
				}
			}
			if q.err != nil {
				return "", jqErr()
			}
			if len(found) != 1 {
				return "", fail("admit.json gives %s the body table %s, and the spec gives it %d bodies", interp(opID), interp(table), len(found))
			}
			var all []string
			if err := fields(q.get(found[0], "schema"), "", nil, &all); err != nil {
				return "", err
			}
			var deduped []any
			for _, f := range all {
				if !contains(deduped, f) {
					deduped = append(deduped, f)
				}
			}
			bodies = append(bodies, body{table: table, id: opID, fields: deduped})
		}
	}
	if q.err != nil {
		return "", jqErr()
	}

	var tables []string
	for _, g := range groupBy(bodies, func(b body) any { return b.table }) {
		var each []any
		for _, b := range g {
			each = append(each, append([]any{}, b.fields...))
		}
		if len(unique(each)) > 1 {
			var ids []any
			for _, b := range g {
				ids = append(ids, b.id)
			}
			return "", fail("the body table %s is named by %s, whose bodies differ", interp(g[0].table), toJSON(ids))
		}
		lines := make([]string, len(g[0].fields))
		for i, f := range g[0].fields {
			lines[i] = toJSON(f)
		}
		tables = append(tables, toJSON(g[0].table)+": [\n"+strings.Join(lines, ",\n")+"\n]")
	}
	return "{\n" + strings.Join(tables, ",\n") + "\n}\n", nil
}
