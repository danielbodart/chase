package gcloud

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/danielbodart/frisket/policy"
)

// The jq that apps/gcloud.nix ran, word for word: the floor the module built,
// and the paths the prepare made of it and the carried APIs' files.
const (
	floorJq = `[.[][] | select(.operation.class == "guarded") | .operation |= del(.description, .category)]`
	pathsJq = `
        def outcome($a): if $a == "ask" then {ask: true} elif $a == "refuse" then {refuse: true} else {} end;
        [inputs[]] + ($floor[0] | map(. + {floor: true}))
        | group_by([.methods, .path, .prefix])
        | map(max_by([(.floor | not), .encodedSlashes // false]) | del(.floor))
        | map(. + outcome({read: "allow", write: $s.writes, guarded: $s.guarded}[.operation.class]))
        + (if $s.unmatched == "allow" then [{methods: $every, prefix: "/"}] else [] end)
      `
)

// Where jq is at hand, the route's rules are the ones the script made, in
// its order, for every tier of the check.
func TestThePathsAreTheScripts(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("no jq to compare with")
	}
	dir := t.TempDir()
	cat := catalogue(t)
	apis, _ := filepath.Glob(filepath.Join(cat, "apis", "*.json"))
	floorFile := filepath.Join(dir, "floor.json")
	out, err := exec.Command(jq, append([]string{"-c", "-s", floorJq}, apis...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(floorFile, out, 0o600)
	floor, err := Floor(cat)
	if err != nil {
		t.Fatal(err)
	}
	everyJSON, _ := json.Marshal(every)
	for name, c := range map[string]struct {
		tier Tier
		apis []string
	}{
		"trusted": {config(t).Tiers["trusted"], []string{"bigquery", "pubsub"}},
		"loose":   {config(t).Tiers["loose"], []string{"bigquery"}},
		"closed":  {config(t).Tiers["closed"], nil},
		// Storage's encoded slashes, and many APIs whose mixins share
		// templates with each other and with the floor.
		"many": {Tier{Writes: "refuse", Guarded: "ask", Unmatched: "ask"}, []string{"compute", "storage", "secretmanager", "iam", "run", "container"}},
	} {
		s, _ := json.Marshal(map[string]any{"writes": c.tier.Writes, "guarded": c.tier.Guarded, "unmatched": c.tier.Unmatched})
		args := []string{"-n", "-c", "--argjson", "s", string(s), "--argjson", "every", string(everyJSON), "--slurpfile", "floor", floorFile, pathsJq}
		var carried []policy.PathRule
		for _, a := range c.apis {
			f := filepath.Join(cat, "apis", a+".json")
			args = append(args, f)
			r, err := rulesOf(f)
			if err != nil {
				t.Fatal(err)
			}
			carried = append(carried, r...)
		}
		out, err := exec.Command(jq, append(args, "/dev/null")...).Output()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want []policy.PathRule
		if err := policy.Decode(out, &want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := paths(c.tier, every, carried, floor)
		if !reflect.DeepEqual(got, want) {
			for i := range min(len(got), len(want)) {
				if !reflect.DeepEqual(got[i], want[i]) {
					g, _ := json.Marshal(got[i])
					w, _ := json.Marshal(want[i])
					t.Errorf("%s: rule %d is\n%s\nnot\n%s", name, i, g, w)
					break
				}
			}
			t.Errorf("%s: %d rules, the script's %d", name, len(got), len(want))
		}
		if len(want) == 0 {
			t.Errorf("%s: nothing to compare", name)
		}
	}
}
