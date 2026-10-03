package checkout

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/danielbodart/chase/internal/gitsafe"
	"github.com/danielbodart/chase/internal/term"
)

// Origin is WHERE A CHECKOUT SAYS IT CAME FROM, for what names it by its
// origin rather than sorts it: the grant, which names a checkout's
// project. The checkout is Find's, found from where the directory is,
// and its origin is read as the selector reads it, from the config files
// alone by gitsafe's git, never by a git that reads the checkout's config
// itself. Every URL is given, not the first, since a checkout with two names
// none of them.
//
// It is the checkout, and what `git config --get-all remote.origin.url`
// printed of each config file, one after another: a URL git would read with
// a newline in it is two lines, which is not one URL either.
func (f *Finder) Origin(ctx context.Context, dir string) (Checkout, string, error) {
	c, err := f.find(ctx, dir)
	if err != nil {
		return Checkout{}, "", err
	}
	urls, err := c.Repo().Config(ctx, f.Git, "remote.origin.url")
	if err != nil {
		return Checkout{}, "", unsortable("the config of %s cannot be read", c.Root)
	}
	return c, gitsafe.StripNUL(urls), nil
}

// RunOrigin is `chase-origin DIR`: ROOT<TAB>HOLDER<TAB>KIND<TAB>GITCOMMON, as
// chase-checkout gives them, then each of origin's URLs on a line of its
// own, and 0; or why the directory cannot be sorted, or its config read, as
// a line, and 1. A usage error is 2. It closes g before it returns.
func RunOrigin(ctx context.Context, g *gitsafe.Git, args []string, stdout, stderr io.Writer) int {
	defer g.Close()
	if len(args) != 1 {
		fmt.Fprintln(stdout, "usage: chase-origin DIR")
		return 2
	}
	c, urls, err := (&Finder{Git: g}).Origin(ctx, args[0])
	return reportFind(err, stdout, stderr, func() {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n%s", c.Root, c.Holder, c.Kind, c.GitCommon, urls)
	})
}

// reportFind is report for a caller of chase-checkout: its failure with no
// reason is said as "cannot find its checkout", as `${out:-...}` said it.
func reportFind(err error, stdout, stderr io.Writer, ok func()) int {
	var u *Unsortable
	var nf *notFound
	switch {
	case err == nil:
		ok()
		return 0
	case errors.As(err, &u):
		fmt.Fprintln(stdout, term.Clean(gitsafe.Output([]byte(u.Reason))))
	case errors.As(err, &nf):
		fmt.Fprintln(stdout, "cannot find its checkout")
		term.Say(stderr, "%v", nf.err)
	default:
		term.Say(stderr, "%v", err)
	}
	return 1
}

// notFound is Find failing with no reason, which its callers said only as
// "cannot find its checkout".
type notFound struct{ err error }

func (n *notFound) Error() string { return n.err.Error() }

// find is Find as its callers had it: a failure with no reason is notFound.
func (f *Finder) find(ctx context.Context, dir string) (Checkout, error) {
	c, err := f.Find(ctx, Query{Dir: dir})
	if err != nil && !errors.As(err, new(*Unsortable)) {
		return Checkout{}, &notFound{err}
	}
	// What the script had of the checkout is what it read back of the line.
	return ReadLine(c.Line()), err
}

// Workspace is what a launch mounts for a session started in pwd: the root of
// the checkout it is in, so all of it is mounted wherever you start;
// otherwise pwd itself, which only a `paths` rule can place. The root is
// Find's, the one the selector sorted: git's own answer is the checkout's to
// steer, with a core.worktree its session wrote, and would mount wherever it
// named. A layout Find will not sort is mounted as the directory alone.
//
// pwd is the shell's $PWD, which is what it prints when the checkout is not
// found: logical, links unresolved.
func (f *Finder) Workspace(ctx context.Context, pwd string) string {
	c, err := f.Find(ctx, Query{Dir: pwd})
	if err != nil {
		return pwd
	}
	return c.Root
}
