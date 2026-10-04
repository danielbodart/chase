package nixstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danielbodart/chase/internal/session"
)

// A SESSION'S STORE, where a test can watch what the host does with it.
// sqlite3, nix-store, nix and systemd-run are each this test binary, run by
// the name of a link to it, as the module runs each at its path: each
// writes down how it was run, beside it in ../logs, and answers as
// fake.json says. Their environment is cleared, so what they are told is
// in that file.

// knobs is fake.json.
type knobs struct {
	Log string
	// Valid is what sqlite3 prints of ValidPaths, one a line; SQLFail
	// makes it fail.
	Valid   []string
	SQLFail bool
	// Invalid is what the host's store does not hold.
	Invalid []string
}

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "sqlite3":
		os.Exit(fakeSqlite())
	case "nix-store":
		os.Exit(fakeNixStore())
	case "nix":
		os.Exit(fakeNix())
	case "systemd-run":
		os.Exit(fakeSystemdRun())
	}
	os.Exit(m.Run())
}

func readKnobs() knobs {
	var k knobs
	b, err := os.ReadFile(filepath.Join(filepath.Dir(os.Args[0]), "fake.json"))
	if err != nil || json.Unmarshal(b, &k) != nil {
		panic("no fake.json beside " + os.Args[0])
	}
	return k
}

// run is one fake's run, as it is written down.
type run struct {
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
}

func logRun(k knobs) {
	b, _ := json.Marshal(run{Argv: os.Args, Env: os.Environ()})
	f, err := os.OpenFile(filepath.Join(k.Log, filepath.Base(os.Args[0])+".jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

func fakeSqlite() int {
	k := readKnobs()
	logRun(k)
	if k.SQLFail {
		fmt.Fprintln(os.Stderr, "Error: malformed database schema")
		return 1
	}
	for _, p := range k.Valid {
		fmt.Println(p)
	}
	return 0
}

func fakeNixStore() int {
	k := readKnobs()
	logRun(k)
	switch {
	case slices.Contains(os.Args, "--check-validity"):
		for _, p := range os.Args[1:] {
			if slices.Contains(k.Invalid, p) {
				fmt.Println(p)
			}
		}
	case slices.Contains(os.Args, "--add-root"):
		// The root, as nix-store makes an indirect one: a link to the
		// path, here to the file fakeNix wrote in its place.
		link := os.Args[slices.Index(os.Args, "--add-root")+1]
		os.Remove(link)
		os.Symlink(filepath.Join(k.Log, "roots-"+filepath.Base(filepath.Dir(link))), link)
	}
	return 0
}

// fakeNix is `nix eval --raw`, CHASE_NIX_ROOTS naming the list: the list,
// read as nix would, written to a file of the store's, here a file in the
// logs named as a store path, whose name it prints.
func fakeNix() int {
	k := readKnobs()
	logRun(k)
	list := os.Getenv("CHASE_NIX_ROOTS")
	b, err := os.ReadFile(list)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var names []string
	if json.Unmarshal(b, &names) != nil {
		fmt.Fprintln(os.Stderr, "error: not JSON")
		return 1
	}
	file := filepath.Join(k.Log, "roots-"+filepath.Base(filepath.Dir(list)))
	os.WriteFile(file, []byte(strings.Join(names, "\n")), 0o444)
	fmt.Print(path('r', "chase-nix-roots"))
	return 0
}

func fakeSystemdRun() int {
	logRun(readKnobs())
	return 0
}

type harness struct {
	t        *testing.T
	dir, bin string
	k        knobs
	n        session.Nix
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, bin: dir + "/bin"}
	for _, d := range []string{"bin", "logs", "sessions"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sqlite3", "nix-store", "nix", "systemd-run"} {
		if err := os.Symlink(self, filepath.Join(h.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	h.k = knobs{Log: dir + "/logs"}
	h.n = session.Nix{
		Timeout: 60, Nix: h.bin + "/nix", Nixpkgs: "/nix/store/nixpkgs-src", System: "x86_64-linux",
		Store: "session", DevShell: "granted",
		Session: &session.NixSession{
			Root: dir + "/sessions", Nix: "/nix/store/nix-ro/bin/nix", Devshell: "/nix/store/chase/bin/chase-devshell",
			NixStore: h.bin + "/nix-store", Sqlite: h.bin + "/sqlite3", SystemdRun: h.bin + "/systemd-run",
			ConfDir: "/etc/nix", MaxBytes: 1 << 20, MaxInodes: 100, MaxRoots: 3, Promote: true,
		},
	}
	h.write()
	return h
}

// write puts the knobs, as they are now, where the fakes read them.
func (h *harness) write() {
	h.t.Helper()
	b, _ := json.Marshal(h.k)
	if err := os.WriteFile(h.bin+"/fake.json", b, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// runs is each run a fake wrote down, in order.
func (h *harness) runs(name string) []run {
	b, err := os.ReadFile(filepath.Join(h.k.Log, name+".jsonl"))
	if err != nil {
		return nil
	}
	var out []run
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r run
		if json.Unmarshal([]byte(l), &r) != nil {
			h.t.Fatalf("a run is not JSON: %s", l)
		}
		out = append(out, r)
	}
	return out
}

// made is a session's store as binds makes it, its upper and the store's
// database as a session would have left them: each of upper, a store
// path's name, made in the upper, read-only, as nix leaves one.
func (h *harness) made(machine string, upper ...string) string {
	h.t.Helper()
	if err := Binds(h.n.Session, machine, &strings.Builder{}, &strings.Builder{}); err != nil {
		h.t.Fatal(err)
	}
	dir := filepath.Join(h.n.Session.Root, machine)
	h.t.Cleanup(func() { remove(dir) })
	for _, d := range []string{"layers/upper", "layers/work", "state/db"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	os.WriteFile(filepath.Join(dir, "state/db/db.sqlite"), []byte("SQLite format 3\x00"), 0o644)
	for _, name := range upper {
		p := filepath.Join(dir, "layers/upper", name)
		os.MkdirAll(p+"/bin", 0o755)
		os.WriteFile(p+"/bin/tool", []byte("#!/bin/sh\n"), 0o555)
		os.Chmod(p+"/bin", 0o555)
		os.Chmod(p, 0o555)
	}
	return dir
}

// path is a store path of name, its hash made of c.
func path(c byte, name string) string {
	return "/nix/store/" + strings.Repeat(string(c), 32) + "-" + name
}
