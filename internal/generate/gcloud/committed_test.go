package gcloud

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The committed table, regenerated: what scripts/gcloud.sh wrote is what
// the port writes, byte for byte, from the same pinned sources. The sources
// are two repositories at pinned commits, fetched over the network, so the
// test runs only when it is given them:
//
//	CHASE_GCLOUD_DISCOVERY=DIR CHASE_GCLOUD_GOOGLEAPIS=DIR  checkouts of the pinned commits (the local mode)
//	CHASE_GCLOUD_FETCH=1                                    fetch them, as the pinned mode does
//
// and is skipped otherwise: a build has no network.
func TestRegeneratesTheCommittedTable(t *testing.T) {
	var args []string
	switch {
	case os.Getenv("CHASE_GCLOUD_DISCOVERY") != "" && os.Getenv("CHASE_GCLOUD_GOOGLEAPIS") != "":
		args = []string{os.Getenv("CHASE_GCLOUD_DISCOVERY"), os.Getenv("CHASE_GCLOUD_GOOGLEAPIS")}
	case os.Getenv("CHASE_GCLOUD_FETCH") == "1":
	default:
		t.Skip("the pinned sources are fetched from GitHub: set CHASE_GCLOUD_DISCOVERY and CHASE_GCLOUD_GOOGLEAPIS to checkouts of them, or CHASE_GCLOUD_FETCH=1")
	}
	need(t, "protoc", "git")
	committed := filepath.Join("..", "..", "..", "apps", "gcloud")
	app := filepath.Join(t.TempDir(), "gcloud")
	copyTree(t, committed, app)
	var stdout, stderr bytes.Buffer
	if code := Main(Config{App: app}, args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s%s", code, stdout.String(), stderr.String())
	}
	t.Logf("%s", stderr.String())
	compareTrees(t, committed, app)
}

// The committed pins are what a bump at the pinned commits would pin: what
// the classification reads of the pinned sources is exactly what
// source.json pins, so a bump at the same commits changes nothing. Given
// checkouts of the pinned commits, as above.
func TestThePinsAreWhatTheClassificationReads(t *testing.T) {
	discovery, googleapis := os.Getenv("CHASE_GCLOUD_DISCOVERY"), os.Getenv("CHASE_GCLOUD_GOOGLEAPIS")
	if discovery == "" || googleapis == "" {
		t.Skip("set CHASE_GCLOUD_DISCOVERY and CHASE_GCLOUD_GOOGLEAPIS to checkouts of the pinned commits")
	}
	need(t, "protoc")
	app := filepath.Join("..", "..", "..", "apps", "gcloud")
	source, err := loadObject(filepath.Join(app, "source.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	for _, e := range source.vals["googleapis"].(*object).vals["entries"].([]any) {
		entries = append(entries, e.(string))
	}
	tmp := t.TempDir()
	list, desc := filepath.Join(tmp, "entries"), filepath.Join(tmp, "d.pb")
	if err := os.WriteFile(list, []byte(lines(entries)), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("protoc", append([]string{"-I", ".", "--include_imports", "--include_source_info", "--descriptor_set_out=" + desc}, entries...)...)
	cmd.Dir = googleapis
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("protoc: %v: %s", err, out)
	}
	pins, err := Pins(app, filepath.Join(discovery, "discoveries"), googleapis, desc, list)
	if err != nil {
		t.Fatal(err)
	}
	keys := func(repo string) string {
		ks := append([]string(nil), source.vals[repo].(*object).vals["files"].(*object).keys...)
		sort.Strings(ks)
		return strings.Join(ks, "\n")
	}
	if got, want := strings.Join(pins.Discovery, "\n"), keys("discovery"); got != want {
		t.Errorf("the Discovery files read are not the pinned ones")
	}
	if got, want := strings.Join(pins.Googleapis, "\n"), keys("googleapis"); got != want {
		t.Errorf("the googleapis files read are not the pinned ones")
	}
	if got, want := strings.Join(pins.Entries, "\n"), strings.Join(entries, "\n"); got != want {
		t.Errorf("the entries are not the pinned ones")
	}
}

func need(t *testing.T, commands ...string) {
	t.Helper()
	for _, c := range commands {
		if _, err := exec.LookPath(c); err != nil {
			t.Skipf("%s is not on PATH: the generator runs it, as the script did (nix develop has it)", c)
		}
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// compareTrees fails for every file of want that got does not have byte
// for byte, and every file got has that want does not.
func compareTrees(t *testing.T, want, got string) {
	t.Helper()
	seen := map[string]bool{}
	filepath.Walk(want, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(want, path)
		seen[rel] = true
		w, _ := os.ReadFile(path)
		g, err := os.ReadFile(filepath.Join(got, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			return nil
		}
		if !bytes.Equal(w, g) {
			wl, gl := strings.Split(string(w), "\n"), strings.Split(string(g), "\n")
			for i := 0; i < len(wl) || i < len(gl); i++ {
				var a, b string
				if i < len(wl) {
					a = wl[i]
				}
				if i < len(gl) {
					b = gl[i]
				}
				if a != b {
					t.Errorf("%s differs at line %d:\nwant %s\n got %s", rel, i+1, a, b)
					break
				}
			}
		}
		return nil
	})
	filepath.Walk(got, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(got, path)
		if !seen[rel] {
			t.Errorf("%s is written but not committed", rel)
		}
		return nil
	})
}
