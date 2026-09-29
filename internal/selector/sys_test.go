package selector_test

import (
	"os"

	"golang.org/x/sys/unix"
)

func mkfifo(path string) error { return unix.Mkfifo(path, 0o644) }

// truncate makes path a sparse file of size bytes, as `truncate -s` does.
func truncate(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
