package grant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/danielbodart/frisket/projpolicy"

	"github.com/danielbodart/chase/internal/term"
)

// The commands a person runs on a project's file: check, fmt, schema,
// sign (sign.go) and migrate.

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

// MigrateCommand is `chase migrate [DIR]`: the checkout's chase.jsonc
// written as the chase.json it says (File.V2) with what a launch derives
// of the checkout, the comments it held said on stderr, since a chase.json
// has none, chase.jsonc removed, and the new file signed.
func MigrateCommand(ctx context.Context, c Config, args []string, stdout, stderr io.Writer) error {
	dir := "."
	switch len(args) {
	case 0:
	case 1:
		dir = args[0]
	default:
		return errors.New("usage: chase migrate [DIR]")
	}
	root, err := Root(dir)
	if err != nil {
		return err
	}
	legacy := root + "/" + LegacyName
	b, err := projpolicy.ReadFile(legacy)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(root + "/" + FileName); err == nil {
		return fmt.Errorf("%s has a %s already: compare the two, and remove %s", root, FileName, LegacyName)
	}
	doc, comments, err := Migrate(b)
	if err != nil {
		return fmt.Errorf("%s: %w", legacy, err)
	}
	for _, cm := range comments {
		term.Say(stderr, "%s: dropped comment: %s", LegacyName, cm)
	}
	g, err := newGit(c)
	if err != nil {
		return err
	}
	defer g.Close()
	if err := c.derive(ctx, g, root, doc, stderr); err != nil {
		return fmt.Errorf("%s: %w", legacy, err)
	}
	out, err := encodeDoc(doc)
	if err != nil {
		return err
	}
	if _, _, err := ParseDoc(out); err != nil {
		return fmt.Errorf("%s would not be a chase.json chase reads: %w", legacy, err)
	}
	mode := os.FileMode(0o644)
	if fi, err := os.Lstat(legacy); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeBeside(root+"/"+FileName, out, mode); err != nil {
		return err
	}
	if err := os.Remove(legacy); err != nil {
		return err
	}
	term.Say(stdout, "%s: written from %s, which is removed", root+"/"+FileName, LegacyName)
	if err := c.sign(ctx, g, root, stdout, stderr); err != nil {
		return fmt.Errorf("%s is not signed (%w): chase sign signs it", FileName, err)
	}
	return nil
}

// Migrate is a chase.jsonc's grant as a chase.json, and its comments: what
// `chase migrate` writes, less what is derived of the checkout.
func Migrate(b []byte) (map[string]any, []string, error) {
	comments, err := Comments(b)
	if err != nil {
		return nil, nil, err
	}
	out, err := ParseFile(b)
	if err != nil {
		return nil, nil, err
	}
	var f File
	if err := strict(out, &f); err != nil {
		return nil, nil, err
	}
	doc, err := f.V2()
	if err != nil {
		return nil, nil, err
	}
	return doc, comments, nil
}
