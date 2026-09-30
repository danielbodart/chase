//go:build race

package selector_test

// race is whether the race detector is on, for a test whose cost is its size
// alone: one that reads tens of megabytes a line at a time on one goroutine
// takes the detector minutes and gives it nothing to find.
const race = true
