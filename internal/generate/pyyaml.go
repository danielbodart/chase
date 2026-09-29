package generate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// A YAML spec is read as scripts/operations.sh read it: by PyYAML's
// safe_load, dumped as JSON by Python and read by jq. That is YAML 1.1, not
// the 1.2 that yaml.v3 resolves plain scalars by -- `on` and `yes` are
// booleans, a number needs a dot to be a float, 0755 is octal, 1:30 is
// sexagesimal, 2001-12-14 is a date that JSON cannot hold -- and it merges
// `<<` keys. So yaml.v3 only parses, into nodes, and what each node is, is
// decided here by PyYAML's rules; and what JSON makes of a Python value --
// a float by its repr, a key that is not a string by json.dumps's words for
// it -- is what jq read.

var (
	yamlBool      = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	yamlFloat     = regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	yamlInt       = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	yamlMerge     = regexp.MustCompile(`^(?:<<)$`)
	yamlNull      = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	yamlTimestamp = regexp.MustCompile(`^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$`)
	yamlValue     = regexp.MustCompile(`^(?:=)$`)
)

// pyResolvers are PyYAML's implicit resolvers, in the order they were added,
// each with the first characters it is tried for.
var pyResolvers = []struct {
	tag   string
	re    *regexp.Regexp
	first string
	empty bool
}{
	{"bool", yamlBool, "yYnNtTfFoO", false},
	{"float", yamlFloat, "-+0123456789.", false},
	{"int", yamlInt, "-+0123456789", false},
	{"merge", yamlMerge, "<", false},
	{"null", yamlNull, "~nN", true},
	{"timestamp", yamlTimestamp, "0123456789", false},
	{"value", yamlValue, "=", false},
}

// pyResolve is the tag PyYAML gives a plain scalar.
func pyResolve(v string) string {
	for _, r := range pyResolvers {
		if v == "" {
			if r.empty {
				return r.tag
			}
			continue
		}
		if strings.ContainsRune(r.first, rune(v[0])) && r.re.MatchString(v) {
			return r.tag
		}
	}
	return "str"
}

// readYAML is the one document in data as jq read it from PyYAML's JSON.
func readYAML(data []byte) (any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("expected a single document in the stream, but found another document")
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	c := &pyConstructor{active: map[*yaml.Node]bool{}}
	return c.value(doc.Content[0])
}

type pyConstructor struct {
	// active are the collections being built, through which an alias back
	// is a circular reference, which json.dump refuses.
	active map[*yaml.Node]bool
}

func (c *pyConstructor) value(n *yaml.Node) (any, error) {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	tag := ""
	if n.Style&yaml.TaggedStyle != 0 {
		tag = n.Tag
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return c.scalar(n, tag)
	case yaml.SequenceNode:
		if tag != "" && tag != "!!seq" {
			return nil, fmt.Errorf("line %d: %s is not a sequence JSON can hold", n.Line, tag)
		}
		if c.active[n] {
			return nil, errors.New("Circular reference detected")
		}
		c.active[n] = true
		defer delete(c.active, n)
		out := []any{}
		for _, e := range n.Content {
			v, err := c.value(e)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		if tag != "" && tag != "!!map" {
			return nil, fmt.Errorf("line %d: %s is not a mapping JSON can hold", n.Line, tag)
		}
		if c.active[n] {
			return nil, errors.New("Circular reference detected")
		}
		c.active[n] = true
		defer delete(c.active, n)
		pairs, err := c.flatten(n)
		if err != nil {
			return nil, err
		}
		out := NewObject()
		for _, p := range pairs {
			k, err := c.key(p[0])
			if err != nil {
				return nil, err
			}
			v, err := c.value(p[1])
			if err != nil {
				return nil, err
			}
			out.Set(k, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("line %d: a node PyYAML would not construct", n.Line)
}

// flatten is PyYAML's flatten_mapping: each `<<` key's mapping, or each of
// its sequence of mappings, is put before the mapping's own pairs -- the
// later of a sequence first, so that the earlier, set after it, wins -- and
// the own pairs, set last, win over all of them.
func (c *pyConstructor) flatten(n *yaml.Node) ([][2]*yaml.Node, error) {
	var merge, own [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if !isMergeKey(k) {
			own = append(own, [2]*yaml.Node{k, v})
			continue
		}
		for v.Kind == yaml.AliasNode {
			v = v.Alias
		}
		switch v.Kind {
		case yaml.MappingNode:
			sub, err := c.flatten(v)
			if err != nil {
				return nil, err
			}
			merge = append(merge, sub...)
		case yaml.SequenceNode:
			var subs [][][2]*yaml.Node
			for _, s := range v.Content {
				for s.Kind == yaml.AliasNode {
					s = s.Alias
				}
				if s.Kind != yaml.MappingNode {
					return nil, fmt.Errorf("line %d: expected a mapping for merging", s.Line)
				}
				sub, err := c.flatten(s)
				if err != nil {
					return nil, err
				}
				subs = append(subs, sub)
			}
			for i := len(subs) - 1; i >= 0; i-- {
				merge = append(merge, subs[i]...)
			}
		default:
			return nil, fmt.Errorf("line %d: expected a mapping or list of mappings for merging", v.Line)
		}
	}
	return append(merge, own...), nil
}

func isMergeKey(k *yaml.Node) bool {
	if k.Kind != yaml.ScalarNode {
		return false
	}
	if k.Style&yaml.TaggedStyle != 0 {
		return k.Tag == "!!merge"
	}
	return plain(k) && pyResolve(k.Value) == "merge"
}

func plain(n *yaml.Node) bool {
	return n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0
}

// key is a mapping key as json.dumps writes it: a string as it is, a number
// as Python prints it, a boolean or None as JSON's words for them. A
// sequence or mapping is no key at all.
func (c *pyConstructor) key(n *yaml.Node) (string, error) {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("line %d: found unhashable key", n.Line)
	}
	tag := ""
	if n.Style&yaml.TaggedStyle != 0 {
		tag = n.Tag
	} else if plain(n) && pyResolve(n.Value) == "value" {
		// A `=` key is a string, as flatten_mapping makes it.
		return n.Value, nil
	}
	v, err := c.scalar(n, tag)
	if err != nil {
		return "", err
	}
	switch v := v.(type) {
	case nil:
		return "null", nil
	case bool:
		return strconv.FormatBool(v), nil
	case Number:
		return string(v), nil
	case Double:
		switch {
		case math.IsNaN(float64(v)):
			return "NaN", nil
		case v > 0:
			return "Infinity", nil
		}
		return "-Infinity", nil
	case string:
		return v, nil
	}
	return "", fmt.Errorf("line %d: an unsupported key", n.Line)
}

// scalar is a scalar node's value, by its explicit tag, or else by PyYAML's
// resolution of a plain scalar; a quoted or block scalar is a string.
func (c *pyConstructor) scalar(n *yaml.Node, tag string) (any, error) {
	kind := "str"
	switch {
	case tag != "":
		kind = strings.TrimPrefix(tag, "!!")
		if kind == tag {
			return nil, fmt.Errorf("line %d: could not determine a constructor for the tag %s", n.Line, tag)
		}
	case plain(n):
		kind = pyResolve(n.Value)
	}
	v := n.Value
	switch kind {
	case "str":
		return v, nil
	case "null":
		return nil, nil
	case "bool":
		switch strings.ToLower(v) {
		case "yes", "true", "on":
			return true, nil
		case "no", "false", "off":
			return false, nil
		}
		return nil, fmt.Errorf("line %d: %q is not a boolean", n.Line, v)
	case "int":
		i, err := pyInt(v)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n.Line, err)
		}
		return Number(i.String()), nil
	case "float":
		f, err := pyFloat(v)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n.Line, err)
		}
		// json.dump writes Infinity and NaN, which are not JSON; jq reads
		// them, as the largest double and as NaN.
		switch {
		case math.IsNaN(f):
			return Double(f), nil
		case math.IsInf(f, 1):
			return Double(math.MaxFloat64), nil
		case math.IsInf(f, -1):
			return Double(-math.MaxFloat64), nil
		}
		return Number(pyRepr(f)), nil
	case "timestamp":
		return nil, fmt.Errorf("line %d: %s is a timestamp, which is not JSON serializable", n.Line, v)
	}
	return nil, fmt.Errorf("line %d: could not determine a constructor for the tag %s", n.Line, tag)
}

// pyInt is PyYAML's construct_yaml_int.
func pyInt(s string) (*big.Int, error) {
	v := strings.ReplaceAll(s, "_", "")
	if v == "" {
		return nil, fmt.Errorf("%q is not an int", s)
	}
	sign := int64(1)
	if v[0] == '-' {
		sign = -1
	}
	if v[0] == '-' || v[0] == '+' {
		v = v[1:]
	}
	parse := func(digits string, base int) (*big.Int, error) {
		i, ok := new(big.Int).SetString(digits, base)
		if !ok || digits == "" || strings.ContainsAny(digits, "+-") {
			return nil, fmt.Errorf("%q is not an int", s)
		}
		return i.Mul(i, big.NewInt(sign)), nil
	}
	switch {
	case v == "0":
		return big.NewInt(0), nil
	case strings.HasPrefix(v, "0b"):
		return parse(v[2:], 2)
	case strings.HasPrefix(v, "0x"):
		return parse(v[2:], 16)
	case strings.HasPrefix(v, "0"):
		return parse(v, 8)
	case strings.Contains(v, ":"):
		parts := strings.Split(v, ":")
		total, base := new(big.Int), big.NewInt(1)
		for i := len(parts) - 1; i >= 0; i-- {
			d, ok := new(big.Int).SetString(parts[i], 10)
			if !ok {
				return nil, fmt.Errorf("%q is not an int", s)
			}
			total.Add(total, d.Mul(d, base))
			base = new(big.Int).Mul(base, big.NewInt(60))
		}
		return total.Mul(total, big.NewInt(sign)), nil
	}
	return parse(v, 10)
}

// pyFloat is PyYAML's construct_yaml_float.
func pyFloat(s string) (float64, error) {
	v := strings.ToLower(strings.ReplaceAll(s, "_", ""))
	if v == "" {
		return 0, fmt.Errorf("%q is not a float", s)
	}
	sign := 1.0
	if v[0] == '-' {
		sign = -1
	}
	if v[0] == '-' || v[0] == '+' {
		v = v[1:]
	}
	switch {
	case v == ".inf":
		return sign * math.Inf(1), nil
	case v == ".nan":
		return math.NaN(), nil
	case strings.Contains(v, ":"):
		parts := strings.Split(v, ":")
		total, base := 0.0, 1.0
		for i := len(parts) - 1; i >= 0; i-- {
			d, err := strconv.ParseFloat(parts[i], 64)
			if err != nil {
				return 0, fmt.Errorf("%q is not a float", s)
			}
			total += d * base
			base *= 60
		}
		return sign * total, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("%q is not a float", s)
	}
	return sign * f, nil
}

// pyRepr is Python's repr of a float: the shortest digits that read back
// as it, in positional notation with at least one digit after the point
// where the point falls within 16 digits of the first and after the fourth
// place past it, and in e-notation with a two-digit exponent otherwise.
func pyRepr(f float64) string {
	sign := ""
	if math.Signbit(f) {
		sign, f = "-", -f
	}
	if f == 0 {
		return sign + "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	decpt := x + 1
	if decpt <= -4 || decpt > 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		es := "+"
		if x < 0 {
			es, x = "-", -x
		}
		return fmt.Sprintf("%s%se%s%02d", sign, m, es, x)
	}
	switch {
	case decpt <= 0:
		return sign + "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	}
	return sign + digits[:decpt] + "." + digits[decpt:]
}
