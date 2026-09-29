package generate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// retries is curl's --retry 3: a transient failure -- a timeout, or an
// HTTP 408, 429, 500, 502, 503 or 504 -- is tried again three times, after
// one second, then two, then four, or after what the server's Retry-After
// says.
const retries = 3

// firstDelay is the back-off before the first retry, doubled for each after.
var firstDelay = time.Second

// fetch writes what url answers to path, as `curl -fsSL --retry 3 -o path
// url` did: redirects followed, and any answer of 400 or more a failure.
// What it wrote is only ever read after it hashes as pinned.
func fetch(ctx context.Context, client *http.Client, url, path string) error {
	if client == nil {
		client = http.DefaultClient
	}
	delay := firstDelay
	for attempt := 0; ; attempt++ {
		transient, after, err := fetchOnce(ctx, client, url, path)
		if err == nil {
			return nil
		}
		if !transient || attempt == retries {
			return err
		}
		wait := delay
		if after >= 0 {
			wait = after
		}
		delay *= 2
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// fetchOnce is one try, and where it failed, whether the failure is
// transient and how long the server asked to be left (negative where it did
// not say).
func fetchOnce(ctx context.Context, client *http.Client, url, path string) (transient bool, after time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, -1, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return timeout(err), -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		err := fmt.Errorf("the requested URL returned error: %d", resp.StatusCode)
		switch resp.StatusCode {
		case 408, 429, 500, 502, 503, 504:
			if s, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && s >= 0 {
				return true, time.Duration(s) * time.Second, err
			}
			return true, -1, err
		}
		return false, -1, err
	}
	f, err := os.Create(path)
	if err != nil {
		return false, -1, err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return timeout(err), -1, err
	}
	return false, -1, f.Close()
}

func timeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
