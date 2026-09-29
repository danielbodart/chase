package gcloud

import (
	"errors"
	"strings"
)

// serviceConfig reads what the generator needs of a YAML file beside a
// proto: whether it is a service config (type: google.api.Service), and
// the names in its apis, which is where an API says which mixins it serves.
//
// The port adds no YAML library for two top-level keys: a service config is
// block YAML, its apis a sequence of mappings, and anything else in the
// file is either another top-level key or indented under one, so a reader
// of lines is enough for what Google writes. TestServiceConfigsAsPyYAML
// holds it to what PyYAML reads of every YAML file in a googleapis checkout,
// given one. What it cannot read it refuses rather than guessing: a second
// document, which PyYAML's safe_load refused too, and, in a service
// config, apis written as anything but a block sequence of block mappings
// -- a flow sequence, an item written as a flow mapping (`- {name: X}`),
// an item that is not a mapping, an anchor, alias or tag. gcloud.py read
// the first two and failed on the rest; read here as no names, a service's
// mixins would be lost from the table with nothing said, so each is an
// error that stops the generator.
func serviceConfig(text string) (service bool, apis []string, err error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var typ string
	var apisErr error
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" || line[0] == ' ' || line[0] == '#' || line[0] == '-' || line[0] == '\t' {
			if line == "---" && i == firstContent(lines) {
				continue
			}
			if line == "---" || strings.HasPrefix(line, "--- ") {
				return false, nil, errors.New("a second YAML document, which PyYAML's safe_load refuses")
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = scalar(key)
		raw := strings.TrimSpace(value)
		value = scalar(value)
		switch key {
		case "type":
			typ = value
		case "apis":
			// A key given twice: PyYAML keeps the last.
			apis, apisErr = nil, nil
			switch value {
			case "", "[]", "~", "null", "Null", "NULL":
				if value == "" && !strings.HasPrefix(raw, "'") && !strings.HasPrefix(raw, `"`) {
					var n int
					apis, n, apisErr = sequence(lines[i+1:])
					i += n
				}
			default:
				apisErr = errors.New("apis is not a block sequence, which this reader does not read")
			}
		}
	}
	if typ != "google.api.Service" {
		return false, nil, nil
	}
	if apisErr != nil {
		return true, nil, apisErr
	}
	return true, apis, nil
}

func firstContent(lines []string) int {
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			return i
		}
	}
	return -1
}

// errUnread is a line of apis this reader does not read as PyYAML would.
var errUnread = errors.New("apis holds what is not a block sequence of block mappings, which this reader does not read")

// sequence reads a block sequence of mappings, from the line after its key
// to the next top-level key: each item's name, where it has one. It returns
// how many lines it read, and errUnread for anything but block mappings.
func sequence(lines []string) (names []string, read int, err error) {
	itemIndent, keyIndent := -1, -1
	named, keyed := false, true
	for read < len(lines) {
		line := lines[read]
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			read++
			continue
		}
		if strings.HasPrefix(trimmed, "\t") {
			return nil, read, errUnread
		}
		if indent == 0 && !strings.HasPrefix(trimmed, "-") {
			break
		}
		if itemIndent < 0 {
			if !strings.HasPrefix(trimmed, "-") {
				// apis: is a mapping, not a sequence.
				return nil, read, errUnread
			}
			itemIndent = indent
		}
		if indent < itemIndent {
			// Less indented than the items, but not a top-level key: not
			// YAML PyYAML reads.
			return nil, read, errUnread
		}
		if indent == itemIndent && (trimmed == "-" || strings.HasPrefix(trimmed, "- ")) {
			if !keyed {
				// The item before was empty, which PyYAML reads as None.
				return nil, read, errUnread
			}
			named, keyed = false, false
			rest := strings.TrimLeft(strings.TrimPrefix(trimmed, "-"), " ")
			keyIndent = -1
			if rest == "" {
				read++
				continue
			}
			keyIndent = indent + (len(trimmed) - len(rest))
			trimmed, indent = rest, keyIndent
		} else if indent == itemIndent {
			return nil, read, errUnread
		}
		if keyIndent < 0 {
			keyIndent = indent
		}
		if indent == keyIndent && keyed && (trimmed == "-" || strings.HasPrefix(trimmed, "- ")) {
			// An item of a sequence under the item's last key, which YAML
			// lets sit at that key's own indent: not the item's key.
			read++
			continue
		}
		if indent == keyIndent {
			key, value, ok := mappingLine(trimmed)
			if !ok {
				return nil, read, errUnread
			}
			keyed = true
			if scalar(key) == "name" {
				if strings.ContainsAny(value[:min(len(value), 1)], "{[&*!|>") {
					return nil, read, errUnread
				}
				if named {
					// A key given twice: PyYAML keeps the last.
					names[len(names)-1] = scalar(value)
				} else {
					names = append(names, scalar(value))
					named = true
				}
			}
		}
		read++
	}
	if !keyed {
		return nil, read, errUnread
	}
	return names, read, nil
}

// mappingLine is a block mapping's `key: value` line: its key, and its
// value with the space before it trimmed. A line that begins as a flow
// collection, an anchor, alias or tag, a block scalar, another sequence or
// a complex key is not one, nor is a line with no `: ` (or a final `:`)
// after its key.
func mappingLine(s string) (key, value string, ok bool) {
	if s == "" || strings.ContainsRune("{[&*!|>-?%@`", rune(s[0])) {
		return "", "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
			return s[:i], strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

// scalar is a plain or quoted scalar's value: a plain one ends at a comment.
func scalar(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "#") {
		return ""
	}
	switch {
	case len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'':
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	case len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"':
		r := strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\n`, "\n", `\t`, "\t")
		return r.Replace(s[1 : len(s)-1])
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}
