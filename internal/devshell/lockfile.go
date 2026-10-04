package devshell

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// WHAT A FILTERED TIER'S EVALUATION IS GIVEN. It has no network, so a
// flake's inputs are fetched before it, by chase, into the fetcher cache
// the evaluation then reads (step P): each from a URL chase builds from the
// lock node's own fields, never one the flake's code chose, and only from
// a host the session's allowlist holds, pinned by its narHash. What nix
// itself would fetch for a node that could name any host -- a git
// repository's submodules, a forge's ?host=, a registry's name, a path on
// the host -- is fetched by nothing, and refuses the devShell. A relative
// path is in the snapshot already. A redirect of an allowed host's is
// still nix's to follow; the narHash is what pins what it brings.

// lockNode is what chase reads of a flake.lock node: its locked reference.
type lockNode struct {
	Locked *struct {
		Type    string `json:"type"`
		Owner   string `json:"owner"`
		Repo    string `json:"repo"`
		Rev     string `json:"rev"`
		Host    string `json:"host"`
		URL     string `json:"url"`
		Path    string `json:"path"`
		NarHash string `json:"narHash"`
	} `json:"locked"`
}

var (
	forgeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// sourcehut's owners are ~user.
	srhtOwner = regexp.MustCompile(`^~?[A-Za-z0-9._-]+$`)
	revision  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	narHash   = regexp.MustCompile(`^sha256-[A-Za-z0-9+/]{43}=$`)
)

// offList is lock nodes fetched from names the allowlist does not hold.
type offList struct{ hosts []string }

func (o *offList) Error() string {
	return "flake.lock fetches from names the session's allowlist does not hold: " + strings.Join(o.hosts, ", ")
}

// prefetchOf is the URLs step P fetches for the flake.lock b, sorted, in a
// tier whose allowlist is allow; or why the lock is refused.
func prefetchOf(b []byte, allow []string) ([]string, error) {
	var l struct {
		Nodes map[string]lockNode `json:"nodes"`
		Root  string              `json:"root"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("flake.lock is not one chase reads: %v", err)
	}
	var urls, off []string
	for _, name := range slices.Sorted(maps.Keys(l.Nodes)) {
		if name == l.Root {
			continue
		}
		lk := l.Nodes[name].Locked
		if lk == nil {
			return nil, fmt.Errorf("flake.lock's %s is locked to nothing", name)
		}
		var u, host string
		switch lk.Type {
		case "github", "gitlab", "sourcehut":
			owner := forgeName
			if lk.Type == "sourcehut" {
				owner = srhtOwner
			}
			switch {
			case lk.Host != "":
				return nil, fmt.Errorf("flake.lock's %s is a %s archive from %s: a forge's host is fetched by nothing in a filtered tier", name, lk.Type, lk.Host)
			case !owner.MatchString(lk.Owner) || !forgeName.MatchString(lk.Repo) || !revision.MatchString(lk.Rev) || !narHash.MatchString(lk.NarHash):
				return nil, fmt.Errorf("flake.lock's %s is not a %s archive chase reads: an owner, a repository, a revision and a narHash", name, lk.Type)
			}
			host = forges[lk.Type]
			u = fmt.Sprintf("%s:%s/%s/%s?narHash=%s", lk.Type, lk.Owner, lk.Repo, lk.Rev, url.QueryEscape(lk.NarHash))
		case "tarball", "file":
			p, err := url.Parse(lk.URL)
			switch {
			// What is checked is what nix is given: a URL that reads back
			// otherwise than it was written may be read otherwise by nix.
			case err != nil || p.Scheme != "https" || p.User != nil || p.Port() != "" || p.Hostname() == "" || p.Fragment != "" || p.Opaque != "" || p.String() != lk.URL || strings.ContainsAny(lk.URL, "\\ "):
				return nil, fmt.Errorf("flake.lock's %s is fetched from %q, which is not https://<name>/", name, lk.URL)
			case !narHash.MatchString(lk.NarHash):
				return nil, fmt.Errorf("flake.lock's %s has no narHash to pin it", name)
			}
			host = strings.ToLower(p.Hostname())
			sep := "?"
			if p.RawQuery != "" {
				sep = "&"
			}
			u = lk.Type + "+" + lk.URL + sep + "narHash=" + url.QueryEscape(lk.NarHash)
		case "path":
			if strings.HasPrefix(lk.Path, "/") || lk.Path == "" {
				return nil, fmt.Errorf("flake.lock's %s is a path on the host, which is fetched by nothing in a filtered tier", name)
			}
			// In the snapshot already.
			continue
		case "git":
			return nil, fmt.Errorf("flake.lock's %s is a lock node of type git, fetched by nothing in a filtered tier: its submodules may name any host", name)
		default:
			return nil, fmt.Errorf("flake.lock's %s is a lock node of type %s, fetched by nothing in a filtered tier", name, lk.Type)
		}
		if !allows(allow, host) {
			off = append(off, host)
			continue
		}
		urls = append(urls, u)
	}
	if len(off) > 0 {
		slices.Sort(off)
		return nil, &offList{slices.Compact(off)}
	}
	slices.Sort(urls)
	return slices.Compact(urls), nil
}
