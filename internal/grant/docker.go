package grant

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/dockerproject"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/term"
)

var (
	scpOrigin = regexp.MustCompile(`^git@github\.com:([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$`)
	urlOrigin = regexp.MustCompile(`^(https://|ssh://git@)github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)$`)
)

// Project is A CHECKOUT'S DOCKER PROJECT (docs/docker.md, decision 9): the
// owner/repo its origin names on GitHub. It decides which containers,
// volumes and networks a session may touch, and at which address, so it is
// derived here, from the checkout, and never taken from anything the
// grant says: the session writes that, and would name itself as another
// project to reach its database.
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
// later without the call changing. What chase-origin and chase docker-address
// said on stderr, the script let through, and so does this.
func Project(ctx context.Context, c Config, ws, tier string, stderr io.Writer) (string, error) {
	g, err := newGit(c)
	if err != nil {
		return "", err
	}
	defer g.Close()
	return project(ctx, g, c, ws, tier, stderr)
}

func project(ctx context.Context, g *gitsafe.Git, c Config, ws, _ string, stderr io.Writer) (string, error) {
	// `out=$(chase-origin "$ws" && echo .)`: what it printed, the newlines at
	// its end kept by the dot, or, when it failed, why.
	var out bytes.Buffer
	if rc := checkout.RunOrigin(ctx, g, []string{ws}, &out, stderr); rc != 0 {
		return "", refuse("%s: Docker needs a checkout, and this one cannot be sorted: %s", ws, gitsafe.Output(out.Bytes()))
	}
	lines := strings.Split(gitsafe.StripNUL(out.String()), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	f := gitsafe.Fields(lines[0], gitsafe.Tab, 4)
	root, common, kind, gitcommon := f[0], f[1], f[2], f[3]
	if len(lines) != 2 {
		return "", refuse("%s: Docker needs exactly one origin URL, so its project has a name, and it has %d", ws, len(lines)-1)
	}
	url := strings.TrimSuffix(strings.TrimSuffix(lines[1], "/"), ".git")
	var owner, repo string
	if m := scpOrigin.FindStringSubmatch(url); m != nil {
		owner, repo = m[1], m[2]
	} else if m := urlOrigin.FindStringSubmatch(url); m != nil {
		owner, repo = m[2], m[3]
	} else {
		return "", refuse("%s: origin %s is not github.com/owner/repo, so it names no project", ws, url)
	}
	// ${x,,} under LC_ALL=C: ASCII only, which is all the patterns let in.
	owner, repo = lowerASCII(owner), lowerASCII(repo)
	if repo == "." || repo == ".." {
		return "", refuse("%s: origin %s names no repository", ws, url)
	}
	slug := owner + "/" + repo
	hit := false
	checkouts := c.checkouts()
	for _, s := range slices.Sorted(maps.Keys(checkouts)) {
		for _, pinned := range checkouts[s] {
			p, err := realpathM(pinned)
			if err != nil {
				return "", fmt.Errorf("realpath: %s: %w", pinned, err)
			}
			if root != p && !strings.HasPrefix(root, p+"/") {
				continue
			}
			if s != slug {
				return "", refuse("%s: %s is under %s, where %s is pinned, but its origin says %s", ws, root, p, s, slug)
			}
			if common != p && gitcommon != p+"/.bare" {
				return "", refuse("%s: %s is under %s, where %s is pinned, but is a %s of %s, not of %s", ws, root, p, slug, kind, common, p)
			}
			hit = true
		}
	}
	if paths, pinned := checkouts[slug]; !hit && pinned {
		return "", refuse("%s: its origin says %s, which is pinned at %s, not %s", ws, slug, strings.Join(paths, ", "), root)
	}
	if _, err := address(slug, stderr); err != nil {
		return "", refuse("%s: %s is not a project frisket can route", ws, slug)
	}
	return slug, nil
}

// address is `chase docker-address SLUG`, which said why it refused on
// stderr, as that command does.
func address(slug string, stderr io.Writer) (dockerproject.Project, error) {
	p, err := dockerproject.Of(slug)
	if err != nil && stderr != nil {
		fmt.Fprintf(stderr, "chase docker-address: %v\n", err)
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

// claim is NO TWO PROJECTS AT ONE ADDRESS (I10). The address is a hash of
// the project's name, and 24 bits can be searched in seconds for a repo name
// that lands on another project's: an approval saying `Docker as evil/x at
// 127.101.170.171` would not be compared with shop's by anyone. So an
// address is first come on this host: the projects already approved here
// (<state>/docker/addresses.json, which only this writes, and from which
// nothing is ever removed but by hand), those the tiers pin, and those whose
// names the host's /etc/hosts carries, read as data. The directory is
// locked, not the file, since the file is replaced whole: the same lock the
// script's flock took, so the two agree while both are about.
//
// record false refuses before anyone is asked; record true checks again,
// once the grant is approved, and remembers the project: one that was
// refused approval holds no address.
func claim(c Config, ws, slug, addr string, record bool) error {
	dir := c.state() + "/docker"
	file := dir + "/addresses.json"
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	lock, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	if _, err := os.Stat(file); err != nil {
		if err := os.WriteFile(file, []byte("{}\n"), 0o666); err != nil {
			return err
		}
	}
	held, err := heldLines(file, func(v *value) (*value, error) { return v, nil })
	if err != nil {
		return refuse("%s: %s cannot be read", ws, file)
	}
	if _, err := os.Stat(c.Hosts); err == nil {
		more, err := heldLines(c.Hosts, func(v *value) (*value, error) { return v.index("address") })
		if err != nil {
			return refuse("%s: %s cannot be read", ws, c.Hosts)
		}
		held += "\n" + more
	}
	for _, s := range slices.Sorted(maps.Keys(c.checkouts())) {
		p, err := dockerproject.Of(s)
		if err != nil {
			continue
		}
		held += "\n" + s + "\t" + p.Address
	}
	for _, line := range gitsafe.HereLines(held) {
		f := gitsafe.Fields(line, gitsafe.Tab, 2)
		other, a := f[0], f[1]
		if other != "" && lowerASCII(other) != slug && a == addr {
			return refuse("%s: %s would be at %s, which %s already holds", ws, slug, addr, other)
		}
	}
	if !record {
		return nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	v, err := parseJSON(b)
	if err != nil {
		return err
	}
	if v.kind == '{' {
		if cur, _ := v.optional(slug); cur == addr {
			return nil
		}
	}
	if v.kind != '{' {
		return fmt.Errorf("%s: %s cannot be added to", ws, file)
	}
	v.set(slug, jstr(addr))
	if err := os.WriteFile(file+".new", []byte(v.pretty()+"\n"), 0o666); err != nil {
		return err
	}
	return os.Rename(file+".new", file)
}

// heldLines is `jq -r 'to_entries[] | "\(.key)\t\(.value | F | strings)"'`
// of a file, as a command substitution held it: a line for each entry whose
// F is a string.
func heldLines(file string, f func(*value) (*value, error)) (string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	v, err := parseJSON(b)
	if err != nil {
		return "", err
	}
	keys, vals, err := v.entries()
	if err != nil {
		return "", err
	}
	var lines []string
	for i, k := range keys {
		x, err := f(vals[i])
		if err != nil {
			return "", err
		}
		if x.kind == '"' {
			lines = append(lines, k+"\t"+x.text)
		}
	}
	return gitsafe.TrimNL(strings.Join(lines, "\n")), nil
}

// hostNames is what the approval is read beside (3.8): the names the host
// has of a project. The names are the session's, which frisket answers. On
// the host a name is one only where /etc/chase/docker-hosts.json, which
// nix-config writes with /etc/hosts, gives it this project at this address:
// read as a file, never looked up, since a name /etc/hosts lacks goes to the
// upstream resolver, which a hostile network answers.
func hostNames(c Config, ws, slug string, who dockerproject.Project) ([]string, error) {
	if _, err := os.Stat(c.Hosts); err != nil {
		return []string{}, nil
	}
	cannot := refuse("%s: %s cannot be read", ws, c.Hosts)
	b, err := os.ReadFile(c.Hosts)
	if err != nil {
		return nil, cannot
	}
	v, err := parseJSON(b)
	if err != nil {
		return nil, cannot
	}
	e, err := v.index(slug)
	if err != nil {
		return nil, cannot
	}
	host := []string{}
	if e.kind != '{' {
		return host, nil
	}
	if a := e.members["address"]; a == nil || a.kind != '"' || a.text != who.Address {
		return host, nil
	}
	var theirs []*value
	if n := e.members["names"]; n != nil {
		theirs, _ = n.iterate()
	}
	for _, name := range who.Names {
		if slices.ContainsFunc(theirs, func(x *value) bool { return x.kind == '"' && x.text == name }) {
			host = append(host, name)
		}
	}
	return host, nil
}

// dockerLine says, beside the approval, where the project's Docker is: its
// project, address and names, and which of the names the host has. Its
// ports are the grant's, which the approval shows, and its checkout the
// one launched from, which goes without saying.
func dockerLine(c Config, ws, slug string, who dockerproject.Project, stderr io.Writer) error {
	names := "no names"
	if len(who.Names) > 0 {
		names = strings.Join(who.Names, ", ")
	}
	host, err := hostNames(c, ws, slug, who)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("Docker as %s at %s (%s)", slug, who.Address, names)
	if len(host) == 0 {
		line += fmt.Sprintf("; on this host, %s only", who.Address)
	} else if !slices.Equal(host, who.Names) {
		line += fmt.Sprintf("; on this host, %s and %s only", who.Address, strings.Join(host, ", "))
	}
	term.Say(stderr, "%s", line)
	return nil
}

func dockerTier(c Config, tier string) bool {
	return strings.Contains(" "+strings.Join(c.DockerTiers, " ")+" ", " "+tier+" ")
}

// Show is `chase docker`: where a checkout's containers are, for a person to
// read on the host. Its project and address, the names a session answers,
// which of them this host's /etc/hosts carries (as the approval reads it),
// and the ports last approved for this project: an approval of the checkout
// as another project, before its origin changed, approved none of this
// one's. A tier without Docker still has the address, since nix-config names
// it whatever the tier.
func Show(ctx context.Context, c Config, ws, tier string, stdout, stderr io.Writer) error {
	g, err := newGit(c)
	if err != nil {
		return err
	}
	defer g.Close()
	slug, err := project(ctx, g, c, ws, tier, stderr)
	if err != nil {
		return err
	}
	who, err := address(slug, stderr)
	if err != nil {
		return refuse("%s: %s has no address", ws, slug)
	}
	fmt.Fprintf(stdout, "%s\n  address  %s\n", slug, who.Address)
	if !dockerTier(c, tier) {
		fmt.Fprintf(stdout, "  (no Docker on %s)\n", tier)
		return nil
	}
	session := "(none)"
	if len(who.Names) > 0 {
		session = strings.Join(who.Names, " ")
	}
	fmt.Fprintf(stdout, "  session  %s\n", session)
	host, err := hostNames(c, ws, slug, who)
	if err != nil {
		return err
	}
	shown := "(address only; not in this host's /etc/hosts)"
	if len(host) > 0 {
		shown = strings.Join(host, " ")
	}
	fmt.Fprintf(stdout, "  host     %s\n", shown)
	var out bytes.Buffer
	if rc := checkout.RunOrigin(ctx, g, []string{ws}, &out, stderr); rc != 0 {
		return refuse("%s: its checkout cannot be sorted: %s", ws, gitsafe.Output(out.Bytes()))
	}
	root, _, _ := strings.Cut(gitsafe.Output(out.Bytes()), "\t")
	result := jnull
	if p := c.state() + "/approved/" + key(root) + "/grant.json"; regular(p) {
		b, err := os.ReadFile(p)
		if err == nil {
			result, err = parseJSON(b)
		}
		if err != nil {
			return refuse("%s: its approved grant cannot be read", ws)
		}
	}
	ports, err := approvedPorts(result, slug)
	if err != nil {
		// The script's jq failed inside printf's argument, which printed
		// the line with nothing after it.
		term.Say(stderr, "%v", err)
	}
	fmt.Fprintf(stdout, "  ports    %s\n", ports)
	return nil
}

// approvedPorts is the ports the approved grant gives slug, as `chase
// docker` says them: none unless it was approved as this project.
func approvedPorts(result *value, slug string) (string, error) {
	var ports []string
	if result.kind == '{' {
		if dp := result.members["dockerProject"]; dp != nil && dp.kind == '"' && dp.text == slug {
			pv, err := result.path("apps", "docker", "ports")
			if err != nil {
				return "", err
			}
			items, err := pv.or(&value{kind: '['}).iterate()
			if err != nil {
				return "", err
			}
			for _, x := range items {
				if x.kind == '0' {
					ports = append(ports, x.tostring())
				}
			}
		}
	}
	if len(ports) == 0 {
		return "(none approved)", nil
	}
	return strings.Join(ports, " ") + "   (approved)", nil
}
