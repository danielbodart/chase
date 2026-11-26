package grant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danielbodart/quoin/projpolicy"

	"github.com/danielbodart/chase/internal/term"
)

// The commands a person runs on a project's file: check, fmt, schema and
// sign (sign.go).

func sha256Hex64(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// CheckCommand is `chase check FILE`: FILE read as a launch reads a
// chase.json, as far as it can be without a tier, and said what is wrong
// with on stderr; and whether its signature verifies, on stdout, when the
// allowed signers can be read.
func CheckCommand(c *Config, args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: chase check FILE | chase check -config FILE")
	}
	path := args[0]
	b, err := projpolicy.ReadFile(path)
	if err != nil {
		return err
	}
	if _, _, err := ParseDoc(b); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !projpolicy.Canonical(b) {
		return fmt.Errorf("%s is not in its canonical form: chase fmt %s, or chase sign, which writes it so", path, path)
	}
	if c == nil {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err := Root(filepath.Dir(abs))
	if err != nil {
		return err
	}
	sig, err := projpolicy.ReadFile(abs + projpolicy.SigSuffix)
	if errors.Is(err, os.ErrNotExist) {
		sig = nil
	} else if err != nil {
		return err
	}
	if err := c.verify(root, b, sig); err != nil {
		term.Say(stdout, "%s: not signed (%v): chase sign signs it", path, err)
	} else {
		term.Say(stdout, "%s: signed", path)
	}
	return nil
}

// FmtCommand is `chase fmt [-check] FILE`: FILE in its canonical form, the
// bytes it is signed over, or with -check only whether it is.
func FmtCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("chase fmt", flag.ContinueOnError)
	check := fs.Bool("check", false, "only say whether FILE is canonical")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: chase fmt [-check] FILE")
	}
	path := fs.Arg(0)
	b, err := projpolicy.ReadFile(path)
	if err != nil {
		return err
	}
	if _, _, err := ParseDoc(b); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	f, err := Canonical(b)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if bytes.Equal(f, b) {
		return nil
	}
	if *check {
		return fmt.Errorf("%s is not in its canonical form: chase fmt it, then sign it again", path)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := writeBeside(path, f, fi.Mode().Perm()); err != nil {
		return err
	}
	term.Say(stdout, "%s: formatted; its signature, if any, no longer matches it", path)
	return nil
}
