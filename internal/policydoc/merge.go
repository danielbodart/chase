package policydoc

import (
	"slices"

	"github.com/danielbodart/chase/internal/apps"
	"github.com/danielbodart/frisket/policy"
)

// Merge merges an app a project binds into the session's policy document:
// its routes in place of any the tier had by the same names, after the
// tier's own, and the names it needs added to `allow`, unless the tier allows
// every name. The allowlist it adds to comes out sorted, and each name once,
// as jq's unique made it; one that allows "*" is left as it is.
//
// Only the patch's routes and allow are the document's: its env is the
// session's environment, and not merged here.
func Merge(doc *policy.Document, patch apps.Patch) {
	names := map[string]bool{}
	for _, r := range patch.Routes {
		names[r.Name] = true
	}
	routes := make([]policy.Route, 0, len(doc.Routes)+len(patch.Routes))
	for _, r := range doc.Routes {
		if !names[r.Name] {
			routes = append(routes, r)
		}
	}
	doc.Routes = append(routes, patch.Routes...)
	if slices.Contains(doc.Allow, "*") {
		return
	}
	allow := append(slices.Clone(doc.Allow), patch.Allow...)
	slices.Sort(allow)
	// Never nil: jq's null + [] is [], and a document's allowlist is a list.
	doc.Allow = append([]string{}, slices.Compact(allow)...)
}
