package policydoc

import (
	"slices"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/frisket/policy"
)

// Merge merges an app a project binds into the session's policy document:
// its routes in place of any the tier had by the same names, after the
// tier's own, its SSH routes the same way among the tier's, and the names
// it needs added to `allow`, unless the tier allows every name. The
// allowlist it adds to comes out sorted, and each name once, as jq's unique
// made it; one that allows "*" is left as it is.
//
// Only the patch's routes, SSH routes and allow are the document's: its env
// is the session's environment, and not merged here.
func Merge(doc *policy.Document, patch apps.Patch) {
	doc.Routes = replaced(doc.Routes, patch.Routes, func(r policy.Route) string { return r.Name })
	doc.SSH = replaced(doc.SSH, patch.SSH, func(r policy.SSHRoute) string { return r.Name })
	if slices.Contains(doc.Allow, "*") {
		return
	}
	allow := append(slices.Clone(doc.Allow), patch.Allow...)
	slices.Sort(allow)
	// Never nil: jq's null + [] is [], and a document's allowlist is a list.
	doc.Allow = append([]string{}, slices.Compact(allow)...)
}

// replaced is the tier's list with each of the patch's in place of any of
// the same name, after the tier's own.
func replaced[R any](tier, patch []R, name func(R) string) []R {
	names := map[string]bool{}
	for _, r := range patch {
		names[name(r)] = true
	}
	out := make([]R, 0, len(tier)+len(patch))
	for _, r := range tier {
		if !names[name(r)] {
			out = append(out, r)
		}
	}
	return append(out, patch...)
}
