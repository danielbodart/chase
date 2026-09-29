package gitsafe

import "time"

// SetTimeout shortens a Git's timeout and grace, for a test that waits them
// out.
func SetTimeout(g *Git, timeout, killAfter time.Duration) {
	g.timeout, g.killAfter = timeout, killAfter
}
