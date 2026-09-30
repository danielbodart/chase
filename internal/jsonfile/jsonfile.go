// Package jsonfile reads and writes the JSON files chase edits but does not
// own -- Claude Code's ~/.claude.json and Codex's auth.json -- with
// encoding/json, and holds only the few things the standard library does not
// already do the way those edits need. (Claude Code's .credentials.json is
// only read through it, for its expiresAt; claude does its own refresh.)
//
// A document is decoded whole into generic values (map[string]any, []any,
// string, bool, nil and json.Number) rather than into a struct, so a member
// chase knows nothing of is kept through an edit: the owning program may
// have written fields this code has never heard of, and dropping one would
// be losing that program's data. Numbers stay json.Number, the literal as
// written, so none passes through a float64 and loses its low digits on the
// way back out. What is not kept is the file's key order and layout, which
// nothing reading these files depends on: members come out sorted, two
// spaces an indent.
package jsonfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Decode is data's one JSON value. Whitespace around it is fine; a second
// value, or anything else after it, is an error, since an edit that read only
// the first would write back a file without the rest.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = errors.New("more than one JSON value")
		}
		return nil, err
	}
	return v, nil
}

// Encode is v indented by two spaces and ended with a newline. <, > and &
// are written as themselves: the files are not HTML, and a token or a path
// escaped as < is the same value but no longer the text a person
// grepping the file would look for.
func Encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Object is v as an object to read a member of or set one in: null is a new,
// empty one -- as a missing `projects` or `tokens` is made where a member
// is set in it -- and anything else but an object is not one, which the
// edits refuse rather than overwrite.
func Object(v any) (map[string]any, bool) {
	switch o := v.(type) {
	case nil:
		return map[string]any{}, true
	case map[string]any:
		return o, true
	}
	return nil, false
}

// Or is v, unless it is null or false, when it is alt: what the files'
// defaults have always been taken for, as jq's `//` took them.
func Or(v, alt any) any {
	if v == nil || v == false {
		return alt
	}
	return v
}
