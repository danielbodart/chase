package selector

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/term"
)

// Output is what `agent-tier [--if-gone] DIR` printed: the decision's line,
// TIER<TAB>REASON, cut to its first field -- the tier alone, unless the reason
// had a newline in it, when each line after it is cut too, as `cut -f1` cut
// it. Nothing that reads the tier matches such a line, so a checkout that
// makes one goes to the fallback.
func (s *Selector) Output(ctx context.Context, dir, ignoring string) string {
	tier, reason := s.Decide(ctx, dir, ignoring)
	var b strings.Builder
	for _, line := range gitsafe.ReadLines(tier + "\t" + reason + "\n") {
		first, _, _ := strings.Cut(line, "\t")
		b.WriteString(first + "\n")
	}
	return b.String()
}

// Tier is `$(agent-tier DIR)`: the tier of dir, as a caller had it.
func (s *Selector) Tier(ctx context.Context, dir string) string {
	return gitsafe.Output([]byte(s.Output(ctx, dir, "")))
}

// IfGone is `$(agent-tier --if-gone DIR)`: dir's tier were its own .git
// deleted, as a session working in it could. The guard asks it of a
// sandbox's workspace.
func (s *Selector) IfGone(ctx context.Context, dir string) string {
	return gitsafe.Output([]byte(s.Output(ctx, dir, dir)))
}

// RunAgentTier is agent-tier:
//
//	agent-tier [DIR]            DIR's tier (the working directory's without one)
//	agent-tier --if-gone DIR    DIR's tier were its own .git deleted
//	agent-tier --dry-run DIR... a table of each DIR, its tier and why
//
// It prints and exits as the script did; what it prints for a person is
// cleaned of control bytes first, which the script's was not. term.Clean
// takes every byte from 0x80 to 0x9f for a C1 control, and those are also
// the continuation bytes of many UTF-8 letters (ł, ř, ā, much of Cyrillic
// and Greek), so a path or a tier with one prints with a '?' for that byte,
// and a --dry-run row padded before it was cleaned can be out of line. It closes s before it returns: see
// gitsafe.Git.Close.
func RunAgentTier(ctx context.Context, s *Selector, args []string, stdout, stderr io.Writer) int {
	defer s.Close()
	switch {
	case len(args) > 0 && args[0] == "--if-gone":
		if len(args) < 2 {
			term.Say(stderr, "agent-tier: --if-gone needs a directory")
			return 1
		}
		fmt.Fprint(stdout, term.Clean(s.Output(ctx, args[1], args[1])))
	case len(args) > 0 && args[0] == "--dry-run":
		fmt.Fprint(stdout, row("DIRECTORY", "TIER", "REASON"))
		for _, d := range args[1:] {
			tier, reason := s.Decide(ctx, d, "")
			for _, line := range gitsafe.ReadLines(tier + "\t" + reason + "\n") {
				f := gitsafe.Fields(line, gitsafe.Tab, 2)
				fmt.Fprint(stdout, term.Clean(row(basename(strings.TrimSuffix(d, "/")), f[0], f[1])))
			}
		}
	default:
		dir := ""
		if len(args) > 0 {
			dir = args[0]
		} else {
			wd, err := os.Getwd()
			if err != nil {
				term.Say(stderr, "agent-tier: %v", err)
				return 1
			}
			dir = wd
		}
		fmt.Fprint(stdout, term.Clean(s.Output(ctx, dir, "")))
	}
	return 0
}

// row is `printf '%-26s %-9s %s\n'` under LC_ALL=C, which pads by bytes.
func row(dir, tier, reason string) string {
	return pad(dir, 26) + " " + pad(tier, 9) + " " + reason + "\n"
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// basename is `$(basename P)`: the last component, trailing slashes aside;
// "/" of nothing but slashes. An argument basename would have read as an
// option -- one beginning with '-' -- printed nothing of it.
func basename(p string) string {
	if strings.HasPrefix(p, "-") || p == "" {
		return ""
	}
	t := strings.TrimRight(p, "/")
	if t == "" {
		return "/"
	}
	if i := strings.LastIndexByte(t, '/'); i >= 0 {
		t = t[i+1:]
	}
	return gitsafe.TrimNL(t)
}

// physical is `$(cd "$dir" 2>/dev/null && pwd -P)`: where cd would take the
// shell, links resolved. cd reads a relative directory against the logical
// working directory and removes each ".." with the component before it,
// each component having to be a directory; when that fails it tries the
// directory as it was given, against the physical one. cd "" fails. A
// directory beginning with '-', which cd reads as an option, and CDPATH are
// not followed: that directory fails, and CDPATH is not asked.
func physical(dir string) (string, bool) {
	if dir == "" || strings.HasPrefix(dir, "-") {
		return "", false
	}
	logical := dir
	if !strings.HasPrefix(dir, "/") {
		wd, err := os.Getwd()
		if err != nil {
			return "", false
		}
		logical = strings.TrimSuffix(wd, "/") + "/" + dir
	}
	first := logical
	if c, ok := canonical(logical); ok {
		first = c
	}
	for _, c := range []string{first, dir} {
		if !gitsafe.Searchable(c) {
			continue
		}
		if r, err := gitsafe.Realpath(c); err == nil {
			return gitsafe.TrimNL(r), true
		}
	}
	return "", false
}

// canonical is bash's canonicalisation of an absolute path for cd: "." and
// empty components dropped, ".." taking the component before it away, and
// every component on the way a directory.
func canonical(p string) (string, bool) {
	var stack []string
	path := func() string { return "/" + strings.Join(stack, "/") }
	for _, comp := range strings.Split(p, "/") {
		switch comp {
		case "", ".":
		case "..":
			if len(stack) > 0 {
				if !gitsafe.IsDir(path()) {
					return "", false
				}
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, comp)
			if !gitsafe.IsDir(path()) {
				return "", false
			}
		}
	}
	return path(), true
}
