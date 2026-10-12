package grant

import (
	"fmt"
	"strconv"
	"strings"
)

// How jq wrote a legacy grant's strings and numbers, which is what a grant
// approved before is compared as.

// quote is s as jq writes a string: '"' and '\' escaped, the five controls
// with short escapes by them, every other C0 and DEL as \u00xx, and all else
// -- '/', HTML's characters, U+2028 -- as itself.
func quote(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// The exponents jq's decNumber context holds, as jq 1.8.2 showed them: an
// adjusted exponent above emax overflows, and a coefficient whose exponent is
// below etiny is rounded, half up, until it is etiny -- to zero if nothing is
// left of it.
const (
	emax  = 999999999
	etiny = -1147483646
	// An exponent written with more digits than decNumber reads is this big,
	// whichever way it points.
	exponentTooBig = 2 * emax
)

// overflowed is what jq writes for a literal decNumber could not hold: the
// double it read instead, which is infinite, and which jq writes as the
// largest double there is.
const overflowed = "1.7976931348623157e+308"

// number is a JSON number's literal as jq writes one it did not compute:
// decNumber's scientific string of it, so 1e2 is 1E+2 and 1.50e1 is 15.0,
// and the digits written are all kept -- within decNumber's own limits,
// beyond which jq writes what decNumber made of it, or, past emax, the
// double. Nix never writes such a literal, but a grant approved under jq
// must read as the same grant, whatever was in it.
func number(lit string) string {
	sign := ""
	if strings.HasPrefix(lit, "-") {
		sign, lit = "-", lit[1:]
	}
	mant, exp := lit, 0
	if i := strings.IndexAny(lit, "eE"); i >= 0 {
		mant = lit[:i]
		exp = exponent(lit[i+1:])
	}
	digits := mant
	if i := strings.IndexByte(mant, '.'); i >= 0 {
		digits = mant[:i] + mant[i+1:]
		exp -= len(mant) - i - 1
	}
	digits = strings.TrimLeft(digits, "0")
	switch {
	case digits == "":
		// A zero keeps its exponent, as far as decNumber can hold it.
		digits, exp = "0", max(etiny, min(exp, emax))
	case exp+len(digits)-1 > emax:
		return sign + overflowed
	case exp < etiny:
		digits, exp = roundHalfUp(digits, etiny-exp), etiny
	}
	n := len(digits)
	adjusted := exp + n - 1
	if exp <= 0 && adjusted >= -6 {
		switch {
		case exp == 0:
			return sign + digits
		case n > -exp:
			return sign + digits[:n+exp] + "." + digits[n+exp:]
		default:
			return sign + "0." + strings.Repeat("0", -exp-n) + digits
		}
	}
	s := digits[:1]
	if n > 1 {
		s += "." + digits[1:]
	}
	if adjusted >= 0 {
		return sign + s + "E+" + strconv.Itoa(adjusted)
	}
	return sign + s + "E-" + strconv.Itoa(-adjusted)
}

// exponent is an exponent's digits, and its sign, as decNumber reads them:
// leading zeros are nothing, and more than ten digits, or ten that begin
// above 1, are exponentTooBig.
func exponent(s string) int {
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimLeft(strings.TrimLeft(s, "+-"), "0")
	e := exponentTooBig
	if len(s) < 10 || len(s) == 10 && s[0] <= '1' {
		e, _ = strconv.Atoi("0" + s)
	}
	if neg {
		return -e
	}
	return e
}

// roundHalfUp is digits, which has no leading zero, without its last drop
// digits, and one more if the first of those dropped was 5 or more.
func roundHalfUp(digits string, drop int) string {
	if drop > len(digits) {
		return "0"
	}
	kept, first := digits[:len(digits)-drop], digits[len(digits)-drop]
	if first < '5' {
		if kept == "" {
			return "0"
		}
		return kept
	}
	b := []byte(kept)
	i := len(b) - 1
	for ; i >= 0 && b[i] == '9'; i-- {
		b[i] = '0'
	}
	if i < 0 {
		return "1" + string(b)
	}
	b[i]++
	return string(b)
}

// jqQuote is s as jq writes a JSON string.
func jqQuote(s string) string {
	var b strings.Builder
	quote(&b, s)
	return b.String()
}
