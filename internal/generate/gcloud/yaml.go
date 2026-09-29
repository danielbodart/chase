package gcloud

import (
	"strings"
)

// serviceConfig reads what the generator needs of a YAML file beside a
// proto: whether it is a service config (type: google.api.Service), and
// the names in its apis, which is where an API says which mixins it serves.
//
// The port adds no YAML library for two top-level keys: a service config is
// block YAML, its apis a sequence of mappings, and anything else in the
// file is either another top-level key or indented under one, so a reader
// of lines is enough. Every service config at the pinned commit reads the
// same here as PyYAML read it (TestServiceConfigsAsPyYAML checks, given the
// pinned checkout). What it cannot read -- apis written as a flow
// sequence, a second document -- it says is not a service config's apis
// rather than guessing.
func serviceConfig(text string) (service bool, apis []string) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var typ string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" || line[0] == ' ' || line[0] == '#' || line[0] == '-' || line[0] == '\t' {
			if line == "---" && i == firstContent(lines) {
				continue
			}
			if line == "---" || strings.HasPrefix(line, "--- ") {
				// A second document: PyYAML's safe_load refuses the file.
				return false, nil
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = scalar(key)
		value = scalar(value)
		switch key {
		case "type":
			typ = value
		case "apis":
			apis = nil
			if value != "" {
				// A flow sequence, or apis given as anything but a block
				// sequence: nothing a service config writes.
				continue
			}
			var n int
			apis, n = sequence(lines[i+1:])
			i += n
		}
	}
	if typ != "google.api.Service" {
		return false, nil
	}
	return true, apis
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

// sequence reads a block sequence of mappings, from the line after its key
// to the next top-level key: each item's name, where it has one. It returns
// how many lines it read.
func sequence(lines []string) (names []string, read int) {
	itemIndent, keyIndent := -1, -1
	named := false
	for read < len(lines) {
		line := lines[read]
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			read++
			continue
		}
		if indent == 0 && !strings.HasPrefix(trimmed, "-") {
			break
		}
		if itemIndent < 0 {
			if !strings.HasPrefix(trimmed, "-") {
				break
			}
			itemIndent = indent
		}
		if indent < itemIndent {
			break
		}
		if indent == itemIndent && (trimmed == "-" || strings.HasPrefix(trimmed, "- ")) {
			named = false
			rest := strings.TrimLeft(strings.TrimPrefix(trimmed, "-"), " ")
			keyIndent = -1
			if rest != "" {
				keyIndent = indent + (len(trimmed) - len(rest))
				trimmed, indent = rest, keyIndent
			} else {
				read++
				continue
			}
		} else if indent == itemIndent {
			break
		}
		if keyIndent < 0 {
			keyIndent = indent
		}
		if indent == keyIndent {
			if key, value, ok := strings.Cut(trimmed, ":"); ok && scalar(key) == "name" {
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
	return names, read
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
