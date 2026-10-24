package main

import (
	"slices"
	"strings"
	"testing"
)

// A wrapper's --tier: anywhere before `--` for an agent, since what starts
// it may put its own arguments first, and only first for `chase shell`,
// whose later words are the shell's.
func TestTierFlag(t *testing.T) {
	tiers := []string{"host", "ops"}
	got := func(args []string, leading bool) (string, []string, error) {
		return tierFlag(args, tiers, leading)
	}
	if tier, args, err := got([]string{"--plugin-dir", "/p", "--tier", "host", "-p", "hi"}, false); err != nil || tier != "host" || !slices.Equal(args, []string{"--plugin-dir", "/p", "-p", "hi"}) {
		t.Errorf("after home-manager's arguments: %q %q %v", tier, args, err)
	}
	if tier, args, err := got([]string{"--tier=ops", "-p", "hi"}, false); err != nil || tier != "ops" || !slices.Equal(args, []string{"-p", "hi"}) {
		t.Errorf("--tier=: %q %q %v", tier, args, err)
	}
	if tier, args, err := got([]string{"-p", "--", "--tier", "host"}, false); err != nil || tier != "" || !slices.Equal(args, []string{"-p", "--", "--tier", "host"}) {
		t.Errorf("after --: %q %q %v", tier, args, err)
	}
	if tier, args, err := got([]string{"--tier", "ops", "-c", "id"}, true); err != nil || tier != "ops" || !slices.Equal(args, []string{"-c", "id"}) {
		t.Errorf("chase shell's: %q %q %v", tier, args, err)
	}
	if tier, args, err := got([]string{"-c", "--tier", "ops"}, true); err != nil || tier != "" || !slices.Equal(args, []string{"-c", "--tier", "ops"}) {
		t.Errorf("a shell's own word: %q %q %v", tier, args, err)
	}
	if _, _, err := got([]string{"-p", "--tier"}, false); err == nil || !strings.Contains(err.Error(), "--tier needs a tier: host, ops") {
		t.Errorf("no tier: %v", err)
	}
	if _, _, err := got([]string{"--tier", "nope"}, false); err == nil || err.Error() != "no tier 'nope'; the tiers are host, ops" {
		t.Errorf("an unknown tier: %v", err)
	}
	if tier, args, err := got(nil, false); err != nil || tier != "" || len(args) != 0 {
		t.Errorf("none: %q %q %v", tier, args, err)
	}
}
