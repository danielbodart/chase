package grant

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/danielbodart/chase/internal/checkout"
	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/projectaddr"
	"github.com/danielbodart/chase/internal/term"
)

// dockerLine says, beside the approval, where the project's Docker is: its
// project, address and names. Its ports are the grant's, which the approval
// shows, and its checkout the one launched from, which goes without saying.
func dockerLine(slug string, who projectaddr.Project, stderr io.Writer) {
	names := "no names"
	if len(who.Names) > 0 {
		names = strings.Join(who.Names, ", ")
	}
	term.Say(stderr, "Docker as %s at %s (%s)", slug, who.Address, names)
}

func dockerTier(c Config, tier string) bool {
	return strings.Contains(" "+strings.Join(c.DockerTiers, " ")+" ", " "+tier+" ")
}

// Show is `chase docker`: where a checkout's project is, for a person to
// read on the host. Its project address and the name frisket answers for
// it, which are the project's whatever the tier -- its dev servers are
// forwarded there -- and, in a tier with Docker, the ports last approved
// for this project: an approval of the checkout as another project, before
// its origin changed, approved none of this one's.
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
	names := "(none)"
	if len(who.Names) > 0 {
		names = strings.Join(who.Names, " ")
	}
	fmt.Fprintf(stdout, "%s\n  address  %s\n  names    %s\n", slug, who.Address, names)
	if !dockerTier(c, tier) {
		fmt.Fprintf(stdout, "  (no Docker on %s)\n", tier)
		return nil
	}
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
