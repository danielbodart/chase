package gcloud

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The three classes, in rising strictness: where two decide one thing, the
// stricter is what it is.
var classes = []string{"read", "write", "guarded"}

func classIndex(c string) int {
	for i, x := range classes {
		if x == c {
			return i
		}
	}
	return -1
}

// The mixins: services every API may serve beside its own, from their own
// protos, named in its service config's apis.
var mixins = map[string]bool{
	"google.iam.v1.IAMPolicy":         true,
	"google.cloud.location.Locations": true,
	"google.longrunning.Operations":   true,
}

// depth is how many segments a {+name} before more of the path is spelled
// out as: frisket matches a template segment by segment, so a name of any
// depth is every depth up to this one.
const depth = 12

// natural is what an HTTP method says an operation does.
func natural(verb string) string {
	switch verb {
	case "GET", "HEAD":
		return "read"
	case "DELETE":
		return "guarded"
	}
	return "write"
}

// sentence is the first sentence of a description's first line: up to the
// first '.', '!' or '?' that ends the line or is followed by a space.
func sentence(text string) string {
	line, _, _ := strings.Cut(pyStrip(text), "\n")
	for i, r := range line {
		if r != '.' && r != '!' && r != '?' {
			continue
		}
		next, _ := utf8.DecodeRuneInString(line[i+1:])
		if i+1 == len(line) || pySpace(next) {
			return line[:i+1]
		}
	}
	return line
}

// words is an operation's summary, and its description where that says
// more than the summary.
func words(id, text string) (summary, description string) {
	text = pyStrip(text)
	summary = sentence(text)
	if summary == "" {
		summary = id
	}
	if text != "" && text != summary {
		description = text
	}
	return summary, description
}

var variable = regexp.MustCompile(`^\{[^}]+\}(:[A-Za-z][A-Za-z0-9_]*)?$`)

// segment is one segment of a Discovery path as a template's: a variable
// is "*", keeping a custom verb after it.
func segment(s string) string {
	if !strings.Contains(s, "{") {
		return s
	}
	if m := variable.FindStringSubmatch(s); m != nil {
		return "*" + m[1]
	}
	return "*"
}

// template is a Discovery path as frisket's template.
func template(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		segs[i] = segment(s)
	}
	return "/" + strings.Join(segs, "/")
}

type shape struct {
	kind string // "path" or "prefix"
	path string
}

var (
	reserved     = regexp.MustCompile(`\{\+([^}]+)\}`)
	literalSlash = regexp.MustCompile(`^((?:[A-Za-z0-9_.~-]+|\{x\})/)*$`)
)

// spans is the templates of a path whose {+name} is any number of
// segments, its pattern ending ".*": a prefix where nothing follows, else
// every depth to depth. Nil where nothing literal would bound it.
func spans(path string, params *object) []shape {
	loc := reserved.FindStringSubmatchIndex(path)
	pattern := ""
	if loc != nil {
		p, _ := params.get(path[loc[2]:loc[3]])
		if o, ok := p.(*object); ok {
			if s, ok := o.vals["pattern"].(string); ok {
				pattern = s
			}
		}
	}
	if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, ".*$") {
		return nil
	}
	fixed := strings.ReplaceAll(pattern[1:len(pattern)-3], "[^/]+", "{x}")
	if !literalSlash.MatchString(fixed) {
		return nil
	}
	before, after := path[:loc[0]]+fixed, path[loc[1]:]
	if after == "" {
		prefix := template(before)
		if inner := strings.Trim(prefix, "/"); inner != "" && !versionRank(inner).ok {
			return []shape{{"prefix", prefix}}
		}
		return nil
	}
	if fixed == "" {
		return nil
	}
	out := make([]shape, 0, depth)
	for n := 1; n <= depth; n++ {
		out = append(out, shape{"path", template(before + strings.Repeat("{x}/", n-1) + "{x}" + after)})
	}
	return out
}

var (
	bound   = regexp.MustCompile(`\{[^}=]+=([^}]*)\}`)
	unbound = regexp.MustCompile(`\{[^}]+\}`)
)

// protoTemplate is a google.api.http path as a template, and whether it is
// a prefix; ok is false where "**" is anything but the whole last segment.
func protoTemplate(path string) (tpl string, prefix, ok bool) {
	flat := bound.ReplaceAllString(path, "${1}")
	flat, verb, _ := strings.Cut(unbound.ReplaceAllString(flat, "*"), ":")
	segs := strings.Split(strings.Trim(flat, "/"), "/")
	for i, s := range segs {
		if s == "**" && i < len(segs)-1 {
			return "", false, false
		}
		if strings.Contains(s, "*") && s != "*" && s != "**" {
			return "", false, false
		}
	}
	prefix = segs[len(segs)-1] == "**"
	if prefix && verb != "" {
		return "", false, false
	}
	if prefix {
		segs = segs[:len(segs)-1]
	}
	if verb != "" {
		segs[len(segs)-1] += ":" + verb
	}
	return "/" + strings.Join(segs, "/"), prefix, true
}

// rank is a version's place: its stability (alpha, beta, stable), then its
// major and minor numbers, compared as numbers of any size. ok is false for
// what is not a version.
type rank struct {
	ok           bool
	stability    int
	major, minor string // digits with no leading zeros
}

var stability = map[string]int{"alpha": 0, "beta": 1, "": 2}

// digits is a run of decimal digits, of any script, as Python's \d reads
// them: the run and where it ends.
func digits(s string) (value string, end int) {
	var b strings.Builder
	for end < len(s) {
		r, n := utf8.DecodeRuneInString(s[end:])
		if !unicode.Is(unicode.Nd, r) {
			break
		}
		b.WriteByte(byte('0' + digitValue(r)))
		end += n
	}
	return strings.TrimLeft(b.String(), "0"), end
}

// digitValue is a decimal digit's value: every run of them in Unicode
// starts at a zero.
func digitValue(r rune) int {
	if r >= '0' && r <= '9' {
		return int(r - '0')
	}
	for _, rg := range unicode.Nd.R16 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return int(r-rune(rg.Lo)) % 10
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return int(r-rune(rg.Lo)) % 10
		}
	}
	return 0
}

// versionRank is v(\d+)(?:p\d+)?(alpha|beta)?(\d*) matched whole: each
// part's digits are taken greedily, as the regular expression takes them.
func versionRank(v string) rank {
	if !strings.HasPrefix(v, "v") {
		return rank{}
	}
	s := v[1:]
	major, n := digits(s)
	if n == 0 {
		return rank{}
	}
	s = s[n:]
	if strings.HasPrefix(s, "p") {
		if _, m := digits(s[1:]); m > 0 {
			s = s[1+m:]
		}
	}
	st := ""
	for _, w := range []string{"alpha", "beta"} {
		if strings.HasPrefix(s, w) {
			st, s = w, s[len(w):]
			break
		}
	}
	minor, m := digits(s)
	if m != len(s) {
		return rank{}
	}
	return rank{ok: true, stability: stability[st], major: major, minor: minor}
}

func numCmp(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// compare orders ranks as Python orders their tuples, what is not a version
// below every version.
func (a rank) compare(b rank) int {
	switch {
	case !a.ok && !b.ok:
		return 0
	case !a.ok:
		return -1
	case !b.ok:
		return 1
	case a.stability != b.stability:
		if a.stability < b.stability {
			return -1
		}
		return 1
	}
	if c := numCmp(a.major, b.major); c != 0 {
		return c
	}
	return numCmp(a.minor, b.minor)
}

// packageVersion is the last part of a proto package that is a version.
func packageVersion(pkg string) string {
	parts := strings.Split(pkg, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if versionRank(parts[i]).ok {
			return parts[i]
		}
	}
	return ""
}

// meet is whether one segment can match two template segments.
func meet(a, b string) bool {
	if a == b || a == "*" || b == "*" {
		return true
	}
	if strings.HasPrefix(a, "*:") && strings.HasPrefix(b, "*:") {
		return false
	}
	if strings.HasPrefix(a, "*:") {
		return strings.HasSuffix(b, a[1:])
	}
	return strings.HasPrefix(b, "*:") && strings.HasSuffix(a, b[1:])
}

var (
	reads   = regexp.MustCompile(`^(Get|List|BatchGet)[A-Z]`)
	deletes = regexp.MustCompile(`^(Delete|BatchDelete)[A-Z]`)
)

// aipVerb is the HTTP method an RPC with no HTTP rule would have by AIP's
// naming: Get, List and BatchGet read, Delete and BatchDelete delete.
func aipVerb(method string) string {
	switch {
	case reads.MatchString(method):
		return "GET"
	case deletes.MatchString(method):
		return "DELETE"
	}
	return "POST"
}

// hostOf is re.sub(r"^https://|/.*$", "", url): the scheme and everything
// from the first slash that runs to the end of the string (Python's $ also
// stops before a final newline, which is kept).
func hostOf(url string) string {
	i := 0
	if strings.HasPrefix(url, "https://") {
		i = len("https://")
	}
	for j := i; j < len(url); j++ {
		if url[j] != '/' {
			continue
		}
		rest := url[j:]
		k := strings.IndexByte(rest, '\n')
		if k < 0 {
			return url[i:j]
		}
		if k == len(rest)-1 {
			return url[i:j] + "\n"
		}
	}
	return url[i:]
}

// matchable is whether frisket could match a template as written: one or
// more segments, each literal with none of / * { } ? # % or a space, or "*",
// or "*:verb".
func matchable(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for _, s := range strings.Split(p[1:], "/") {
		if s == "" {
			return false
		}
		if s == "*" || customVerb.MatchString(s) {
			continue
		}
		if strings.ContainsAny(s, "/*{}?#%") || strings.IndexFunc(s, pySpace) >= 0 {
			return false
		}
	}
	return true
}

var customVerb = regexp.MustCompile(`^\*:[A-Za-z][A-Za-z0-9_]*$`)
