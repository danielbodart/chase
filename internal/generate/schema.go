package generate

import (
	"fmt"
	"sort"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
	"github.com/vektah/gqlparser/v2/parser"
)

// A GraphQL schema's operations, what scripts/schema.py read with
// graphql-core: every field of the schema's mutation and subscription types
// -- each an operation a request can hold -- with its description, whether
// it is deprecated and why, and its category: GitHub's @docsCategory, the
// grouping its documentation uses, and the one its REST description calls
// x-github.category. Queries are not listed: a query is a read, whatever it
// reads, and is one operation of its own.
//
// It is read with gqlparser, so a schema is read as GraphQL rather than as
// lines. gqlparser keeps a type's definitions and its extensions apart,
// where graphql-core kept them in the document's order, so they are put
// back in that order by where they begin; and it gives an empty description
// and none alike as "", where graphql-core told them apart -- a field with
// none is refused, one with "" is not -- so whether a string comes before
// the field's name is read from the tokens.
func schemaFields(sdl string) ([]field, error) {
	src := &ast.Source{Name: "schema.graphql", Input: sdl}
	doc, err := parser.ParseSchema(src)
	if err != nil {
		return nil, err
	}
	described, err := describedAt(src)
	if err != nil {
		return nil, err
	}

	// The root types are Mutation and Subscription unless a schema
	// definition names others.
	kinds := []string{"mutation", "subscription"}
	roots := map[string]string{"mutation": "Mutation", "subscription": "Subscription"}
	for _, s := range doc.Schema {
		for _, o := range s.OperationTypes {
			k := string(o.Operation)
			if _, ok := roots[k]; !ok {
				kinds = append(kinds, k)
			}
			roots[k] = o.Type
		}
	}

	defs := append(append(ast.DefinitionList{}, doc.Definitions...), doc.Extensions...)
	sort.SliceStable(defs, func(i, j int) bool { return defs[i].Position.Start < defs[j].Position.Start })

	byKind := map[string][]field{}
	for _, d := range defs {
		if d.Kind != ast.Object {
			continue
		}
		for _, kind := range kinds {
			if d.Name != roots[kind] {
				continue
			}
			for _, f := range d.Fields {
				// The last of a directive given twice, as a dict of them
				// keeps.
				directives := map[string]*ast.Directive{}
				for _, dir := range f.Directives {
					directives[dir.Name] = dir
				}
				entry := field{kind: kind, name: f.Name}
				if described[f.Position.Start] {
					entry.description = f.Description
				}
				if dir, ok := directives["docsCategory"]; ok {
					if entry.category, err = stringArgument(dir, "name"); err != nil {
						return nil, err
					}
				}
				if dir, ok := directives["deprecated"]; ok {
					reason, err := stringArgument(dir, "reason")
					if err != nil {
						return nil, err
					}
					if !pyTruthy(reason) {
						reason = "Deprecated."
					}
					entry.deprecated = reason
				}
				byKind[kind] = append(byKind[kind], entry)
			}
		}
	}
	var out []field
	for _, k := range kinds {
		out = append(out, byKind[k]...)
	}
	return out, nil
}

// stringArgument is a directive's argument's value as graphql-core's node
// gave it: a string, an enum's name or a number's digits as a string, a
// boolean as one; nil where there is no such argument.
func stringArgument(d *ast.Directive, name string) (any, error) {
	for _, a := range d.Arguments {
		if a.Name != name {
			continue
		}
		switch a.Value.Kind {
		case ast.StringValue, ast.BlockValue, ast.EnumValue, ast.IntValue, ast.FloatValue:
			return a.Value.Raw, nil
		case ast.BooleanValue:
			return a.Value.Raw == "true", nil
		}
		return nil, fmt.Errorf("@%s(%s:) is not a value graphql-core's node carries", d.Name, name)
	}
	return nil, nil
}

// pyTruthy is Python's truth for what stringArgument gives.
func pyTruthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	}
	return true
}

// describedAt is the start of every name the source gives a description
// before: the token before it, comments aside, is a string.
func describedAt(src *ast.Source) (map[int]bool, error) {
	l := lexer.New(src)
	out := map[int]bool{}
	prev := lexer.Invalid
	for {
		t, err := l.ReadToken()
		if err != nil {
			return nil, err
		}
		if t.Kind == lexer.EOF {
			return out, nil
		}
		if t.Kind == lexer.Comment {
			continue
		}
		if t.Kind == lexer.Name && (prev == lexer.String || prev == lexer.BlockString) {
			out[t.Pos.Start] = true
		}
		prev = t.Kind
	}
}
