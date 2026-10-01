package dockerproject

import (
	"slices"
	"strings"
	"testing"
)

// The contract's vectors, as frisket's own TestTheDerivationGivesTheContractsVectors
// has them, and chase's own: what a slug is given, through frisket's functions.
func TestASlugIsGivenItsAddressAndNames(t *testing.T) {
	a63, a64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	for _, v := range []struct {
		slug, project, address string
		names                  []string
	}{
		{"example/shop", "example/shop", "127.101.170.171", []string{"shop.example.internal"}},
		{"example/billing", "example/billing", "127.10.146.214", []string{"billing.example.internal"}},
		{"danielbodart/frisket", "danielbodart/frisket", "127.103.202.234", []string{"frisket.danielbodart.internal"}},
		{"test/repo-66", "test/repo-66", "127.211.18.75", []string{"repo-66.test.internal"}},
		{"Example/Shop", "example/shop", "127.101.170.171", []string{"shop.example.internal"}},
		// A "." in the repo stays one, so no two repos share a name.
		{"bodar/bodar.ts", "bodar/bodar.ts", "127.100.84.99", []string{"bodar.ts.bodar.internal"}},
		{"bodar/bodar-ts", "bodar/bodar-ts", "127.113.253.232", []string{"bodar-ts.bodar.internal"}},
		// A DNS label is at most 63 characters.
		{"test/" + a63, "test/" + a63, "127.9.96.222", []string{a63 + ".test.internal"}},
		{"test/" + a64, "test/" + a64, "127.60.34.62", []string{}},
	} {
		got, err := Of(v.slug)
		if err != nil {
			t.Errorf("%s: %v", v.slug, err)
			continue
		}
		if got.Project != v.project || got.Address != v.address || !slices.Equal(got.Names, v.names) {
			t.Errorf("%s: %+v, want %s at %s named %q", v.slug, got, v.project, v.address, v.names)
		}
	}
}

// A repo that is no DNS label has no name -- an empty label, or a '-'
// first -- and a name that is already something else's -- all of
// frisket.internal and google.internal -- is never given.
func TestANameIsGivenOnlyWhereItIsALabelNothingElseHas(t *testing.T) {
	for slug, want := range map[string][]string{
		"test/___":        {"___.test.internal"},
		"test/...":        {},
		"test/_.._":       {},
		"test/-x.-":       {},
		"frisket/docker":  {},
		"google/metadata": {},
		"google/shop":     {},
		"frisket/foo":     {},
		"frisket/frisket": {},
		"google/google":   {},
		"x/frisket":       {"frisket.x.internal"},
	} {
		got, err := Of(slug)
		if err != nil {
			t.Errorf("%s: %v", slug, err)
			continue
		}
		if !slices.Equal(got.Names, want) {
			t.Errorf("%s: named %q, want %q", slug, got.Names, want)
		}
	}
}

// What frisket would refuse as a route's project is refused here, with a
// reason; the longest owner and repo it accepts are accepted.
func TestASlugFrisketWouldRefuseIsRefused(t *testing.T) {
	for _, slug := range []string{
		"example", "example/shop/x", "", strings.Repeat("o", 40) + "/repo",
		"test/..", "test/.", "-test/repo", "test/" + strings.Repeat("r", 101),
		"test/a b", "test/repo\nx", "test/ré", "a/b/c", "evil/../shop", "a/rép", "/x",
	} {
		if got, err := Of(slug); err == nil {
			t.Errorf("%q was given %+v", slug, got)
		} else if err.Error() == "" {
			t.Errorf("%q was refused without a reason", slug)
		}
	}
	for _, slug := range []string{strings.Repeat("o", 39) + "/repo", "test/" + strings.Repeat("r", 100)} {
		if _, err := Of(slug); err != nil {
			t.Errorf("%q: %v", slug, err)
		}
	}
}
