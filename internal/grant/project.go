package grant

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/projectaddr"
)

var (
	scpOrigin = regexp.MustCompile(`^git@github\.com:([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$`)
	urlOrigin = regexp.MustCompile(`^(https://|ssh://git@)github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$`)
)

// Project is A CHECKOUT'S PROJECT: the owner/repo its origin names on
// GitHub, which gives it its PROJECT ADDRESS (internal/projectaddr) -- a
// loopback address and a name of its own, where a session's dev-server
// forwards are bound -- and, with Docker, which containers, volumes and
// networks a session may touch (docs/docker.md, decision 9). So it is
// derived here, from the checkout, and never taken from anything the grant
// says: the session writes that, and would name itself as another project
// to reach its database, or take another's address. A linked worktree is
// served as a project of its own, named for it (servedAs), so its address,
// its name and its containers are its own.
//
// The checkout is chase-checkout's, found from where the directory is, and
// its origin read by checkout.Finder.Origin as the selector reads it: git
// here never reads a checkout's own config, which its session wrote and
// which can name a command for git to run. Its root is that one, never
// git's --show-toplevel, which core.worktree moves.
//
// Held both ways to the checkouts the tiers pin: a pinned project only at its
// own path, and a pinned path only as its own project. And, as the selector's
// in_checkout holds it, only from the repository kept at that path itself or
// in its .bare: a clone nested under the path has a session of its own, which
// writes its own .git, origin included. A project no tier pins is a claim,
// shown in the approval, which a person approves.
//
// tier is not read yet: it is taken so that a tier can say more of a project
// later without the call changing. What chase-origin and chase
// project-address said on stderr, the script let through, and so does this.
func Project(ctx context.Context, c Config, ws, tier string, stderr io.Writer) (checkoutProject, error) {
	g, err := newGit(c)
	if err != nil {
		return checkoutProject{}, err
	}
	defer g.Close()
	return project(ctx, g, c, ws, tier, stderr)
}

// checkoutProject is a checkout's project twice over. Slug is the owner/repo
// its origin names, which its grant is signed, approved and pinned as.
// Served is the one its address and name are of, and its Docker's: the
// same, but in a linked worktree (servedAs).
type checkoutProject struct{ Slug, Served string }

func project(ctx context.Context, g *gitsafe.Git, c Config, ws, _ string, stderr io.Writer) (checkoutProject, error) {
	p, err := slugOf(ctx, g, c, ws, stderr)
	if err != nil {
		return checkoutProject{}, err
	}
	if p.Served != p.Slug {
		if _, err := address(p.Served, stderr); err != nil {
			return checkoutProject{}, refuse("%s: %s is not a project frisket can route", ws, p.Served)
		}
	}
	return p, nil
}

func slugOf(ctx context.Context, g *gitsafe.Git, c Config, ws string, stderr io.Writer) (checkoutProject, error) {
	// `out=$(chase-origin "$ws" && echo .)`: what it printed, the newlines at
	// its end kept by the dot, or, when it failed, why.
	var out bytes.Buffer
	if rc := checkout.RunOrigin(ctx, g, []string{ws}, &out, stderr); rc != 0 {
		return checkoutProject{}, refuse("%s: a project needs a checkout, and this one cannot be sorted: %s", ws, gitsafe.Output(out.Bytes()))
	}
	lines := strings.Split(gitsafe.StripNUL(out.String()), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	f := gitsafe.Fields(lines[0], gitsafe.Tab, 4)
	root, common, kind, gitcommon := f[0], f[1], f[2], f[3]
	if len(lines) != 2 {
		return checkoutProject{}, refuse("%s: a project needs exactly one origin URL, so it has a name, and this has %d", ws, len(lines)-1)
	}
	url := strings.TrimSuffix(strings.TrimSuffix(lines[1], "/"), ".git")
	var owner, repo string
	if m := scpOrigin.FindStringSubmatch(url); m != nil {
		owner, repo = m[1], m[2]
	} else if m := urlOrigin.FindStringSubmatch(url); m != nil {
		owner, repo = m[2], m[3]
	} else {
		return checkoutProject{}, refuse("%s: origin %s is not github.com/owner/repo, so it names no project", ws, url)
	}
	// ${x,,} under LC_ALL=C: ASCII only, which is all the patterns let in.
	owner, repo = lowerASCII(owner), lowerASCII(repo)
	if repo == "." || repo == ".." {
		return checkoutProject{}, refuse("%s: origin %s names no repository", ws, url)
	}
	slug := owner + "/" + repo
	hit := false
	checkouts := c.checkouts()
	for _, s := range slices.Sorted(maps.Keys(checkouts)) {
		for _, pinned := range checkouts[s] {
			p, err := realpathM(pinned)
			if err != nil {
				return checkoutProject{}, fmt.Errorf("realpath: %s: %w", pinned, err)
			}
			if root != p && !strings.HasPrefix(root, p+"/") {
				continue
			}
			if s != slug {
				return checkoutProject{}, refuse("%s: %s is under %s, where %s is pinned, but its origin says %s", ws, root, p, s, slug)
			}
			if common != p && gitcommon != p+"/.bare" {
				return checkoutProject{}, refuse("%s: %s is under %s, where %s is pinned, but is a %s of %s, not of %s", ws, root, p, slug, kind, common, p)
			}
			hit = true
		}
	}
	if paths, pinned := checkouts[slug]; !hit && pinned {
		return checkoutProject{}, refuse("%s: its origin says %s, which is pinned at %s, not %s", ws, slug, strings.Join(paths, ", "), root)
	}
	if _, err := address(slug, stderr); err != nil {
		return checkoutProject{}, refuse("%s: %s is not a project frisket can route", ws, slug)
	}
	served, err := servedAs(slug, kind, root)
	if err != nil {
		return checkoutProject{}, refuse("%s: %v", ws, err)
	}
	return checkoutProject{Slug: slug, Served: served}, nil
}

// servedAs is the project a checkout is SERVED as: its own, or, in a linked
// worktree, <worktree>.<repo> of the same owner, the worktree named by its
// directory. So each worktree has an address and a name of its own --
// fix-login.app.acme.internal beside app.acme.internal -- and its dev
// servers and containers are apart from every other's, while its grant,
// signed, approved and pinned, stays the repository's. frisket reads the
// name back as the repo fix-login.app, so nothing of frisket's changes; a
// repo of that very name, of the same owner, would share the address, as
// two projects whose hashes meet do. The directory is made one label a
// name can carry: lower-case, anything but a letter, a digit, '_' or '-'
// made '-', no '-' first, and cut to fit a label's 63 bytes and frisket's
// 100 of repo. Every worktree of a repository kept in a .bare is one, so
// none of those has the repository's own address.
func servedAs(slug, kind, root string) (string, error) {
	if kind != "worktree" {
		return slug, nil
	}
	owner, repo, _ := strings.Cut(slug, "/")
	label := strings.TrimLeft(strings.Map(func(r rune) rune {
		switch {
		case 'a' <= r && r <= 'z', '0' <= r && r <= '9', r == '_', r == '-':
			return r
		}
		return '-'
	}, lowerASCII(filepath.Base(root))), "-")
	room := min(63, 100-len(repo)-1)
	if room < 1 || label == "" {
		return "", fmt.Errorf("worktree %s gives no name to serve %s as", root, slug)
	}
	if len(label) > room {
		label = label[:room]
	}
	return owner + "/" + label + "." + repo, nil
}

// address is `chase project-address SLUG`: the project's address and name,
// or why there are none, said on stderr as that command says it.
func address(slug string, stderr io.Writer) (projectaddr.Project, error) {
	p, err := projectaddr.Of(slug)
	if err != nil && stderr != nil {
		fmt.Fprintf(stderr, "chase project-address: %v\n", err)
	}
	return p, err
}

func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// realpathM is `realpath -m -- P`: P absolute, every link in it that is
// there resolved, and what is not there taken as it is written.
func realpathM(p string) (string, error) {
	if p == "" {
		return "", syscall.ENOENT
	}
	rest, resolved := p, "/"
	if !strings.HasPrefix(p, "/") {
		wd, err := unix.Getwd()
		if err != nil {
			return "", err
		}
		resolved = wd
	}
	links := 0
	for rest != "" {
		var comp string
		rest = strings.TrimLeft(rest, "/")
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			comp, rest = rest[:i], rest[i:]
		} else {
			comp, rest = rest, ""
		}
		switch comp {
		case "", ".":
			continue
		case "..":
			if i := strings.LastIndexByte(resolved, '/'); i > 0 {
				resolved = resolved[:i]
			} else {
				resolved = "/"
			}
			continue
		}
		next := "/" + comp
		if resolved != "/" {
			next = resolved + "/" + comp
		}
		if fi, err := os.Lstat(next); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if links++; links > 40 {
				return "", syscall.ELOOP
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(target, "/") {
				resolved = "/"
			}
			rest = target + rest
			continue
		}
		resolved = next
	}
	return gitsafe.TrimNL(resolved), nil
}
