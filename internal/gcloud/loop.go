package gcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/danielbodart/chase/internal/term"
)

// Clock is the time the loop reads and waits on: the real one, or a check's.
type Clock interface {
	Now() time.Time
	// Sleep waits for d, or until ctx is done.
	Sleep(ctx context.Context, d time.Duration)
}

// RealClock is the wall clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

func (RealClock) Sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

const (
	// renewBefore is how long before the token's expiry it is renewed: past
	// it frisket answers 503, and clients retry that quietly for about two
	// minutes, so a slow renewal must never leave a gap.
	renewBefore = 600
	// longestNap is how long the loop waits before it looks at the token
	// again, in seconds, however far off its renewal is.
	longestNap = 300
	// retryAfter is how long after a failed mint the next is tried.
	retryAfter = 60
	// napStep is how often a nap looks for RUN: the loop outlives its
	// session by at most this.
	napStep = 10
)

// Loop keeps RUN/gcloud-token.json minted for as long as RUN is there,
// renewing it ten minutes before it expires and trying again a minute after
// a mint fails, whatever the failure: a key Google refuses now may be one it
// takes once the person has fixed it. It returns when RUN is gone, or ctx
// is done.
//
// A non-empty sa is checked on every mint, as the script's loop called the
// same mint under the same $CHASE_GCLOUD_SA. The unit sets none, since the
// launch checked the key before it started this; but a loop that is given
// one refuses another account's key every minute rather than send it.
func Loop(ctx context.Context, cfg Config, run, sa string, stderr io.Writer, clock Clock) {
	for ctx.Err() == nil && isDir(run) {
		// In whole seconds, truncated, as the shell's arithmetic had it.
		wait := (expiry(run)-clock.Now().UnixMilli())/1000 - renewBefore
		if wait > 0 {
			nap(ctx, clock, run, min(wait, longestNap))
			continue
		}
		if Mint(ctx, cfg, run, sa, stderr) != Minted {
			if !isDir(run) || ctx.Err() != nil {
				break
			}
			fmt.Fprint(stderr, term.Clean("chase-gcloud-renew: trying again in a minute")+"\n")
			nap(ctx, clock, run, retryAfter)
		}
	}
}

// nap waits left seconds, in steps, for as long as RUN is there.
func nap(ctx context.Context, clock Clock, run string, left int64) {
	for left > 0 && isDir(run) && ctx.Err() == nil {
		clock.Sleep(ctx, time.Duration(min(left, napStep))*time.Second)
		left -= napStep
	}
}

// expiry is the token's expiry in epoch milliseconds, or 0 if there is no
// token file or it names none: a token to mint now.
func expiry(run string) int64 {
	b, err := os.ReadFile(run + "/gcloud-token.json")
	if err != nil {
		return 0
	}
	var t struct {
		Expiry any `json:"expiry"`
	}
	if json.Unmarshal(b, &t) != nil {
		return 0
	}
	f, ok := t.Expiry.(float64)
	if !ok {
		return 0
	}
	return int64(f)
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
