package nixstore

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// What binds prints of a session's store: the overlay of the host's store,
// its layers in the session's directory, never bound in; the store's state,
// read-write; and the lower's, read-only, the host's database a link in
// it, beside the empty directories a read-only store wants.
func TestBindsMakesTheStoreAndPrintsItsThreeLines(t *testing.T) {
	h := newHarness(t)
	var out, said strings.Builder
	if err := Binds(h.n.Session, "chase-strict-1", &out, &said); err != nil {
		t.Fatal(err)
	}
	dir := h.n.Session.Root + "/chase-strict-1"
	want := "/nix/store:overlay:" + dir + "/layers\n" + dir + "/state:rw\n" + dir + "/lower\n"
	if out.String() != want {
		t.Errorf("printed %q, not %q", out.String(), want)
	}
	if l, err := os.Readlink(dir + "/lower/db"); err != nil || l != "/nix/var/nix/db" {
		t.Errorf("the lower's database is %q, %v", l, err)
	}
	for _, d := range []string{"gcroots/per-user", "profiles/per-user", "temproots", "active-builds"} {
		if fi, err := os.Stat(dir + "/lower/" + d); err != nil || !fi.IsDir() {
			t.Errorf("no lower/%s: %v", d, err)
		}
	}
	if fi, err := os.Stat(dir + "/layers"); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the layers are %v, %v", fi.Mode(), err)
	}
}

// A machine flong would never name is no directory of chase's: refused
// before anything is made.
func TestAMachineThatIsNoPlainNameIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, m := range []string{"", "..", "../x", "a/b", ".hidden", "a b", "a\nb"} {
		if err := Binds(h.n.Session, m, &strings.Builder{}, &strings.Builder{}); err == nil {
			t.Errorf("%q was taken", m)
		}
	}
	if entries, _ := os.ReadDir(h.n.Session.Root); len(entries) != 0 {
		t.Errorf("made %v", entries)
	}
}

// A directory of the same machine's, a launch's that died, is nothing of
// this one's: it is made afresh.
func TestAnEarlierSessionsDirectoryOfTheSameMachineIsMadeAfresh(t *testing.T) {
	h := newHarness(t)
	dir := h.made("m1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-planted")
	if err := Binds(h.n.Session, "m1", &strings.Builder{}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir + "/layers/upper"); err == nil {
		t.Error("the earlier session's upper is still there")
	}
}

// $binds shows the overlay without its layers.
func TestMadeIsTheOverlayInBinds(t *testing.T) {
	for binds, want := range map[string]bool{
		"/w/other:rw\n/nix/store:overlay\n/home/a/.cache/s/m/state:rw": true,
		"/nix/store:overlay":                true,
		"/nix/store:rw":                     false,
		"/nix/store:overlay:/home/a/layers": false,
		"":                                  false,
	} {
		if Made(binds) != want {
			t.Errorf("%q: %v", binds, !want)
		}
	}
}

// The session's nix is told a local-overlay store over the host's, its
// upper named and its mount not checked, the lower read-only from the
// lower's state; its log in the store's state; the container's
// configuration and no user's.
func TestTheSessionsNixIsToldItsStore(t *testing.T) {
	h := newHarness(t)
	env, err := Env(h.n.Session, "m1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range env {
		got[v.Name] = v.Value
	}
	dir := h.n.Session.Root + "/m1"
	if got["NIX_LOG_DIR"] != dir+"/state/log" || got["NIX_CONF_DIR"] != "/etc/nix" {
		t.Errorf("told %v", got)
	}
	if v, ok := got["NIX_USER_CONF_FILES"]; !ok || v != "" {
		t.Errorf("NIX_USER_CONF_FILES is %q, %v", v, ok)
	}
	store, ok := strings.CutPrefix(got["NIX_REMOTE"], "local-overlay://?")
	if !ok {
		t.Fatalf("NIX_REMOTE is %q", got["NIX_REMOTE"])
	}
	q, err := url.ParseQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("real") != "/nix/store" || q.Get("state") != dir+"/state" || q.Get("upper-layer") != dir+"/layers/upper" || q.Get("check-mount") != "false" {
		t.Errorf("the store is %v", q)
	}
	lower, ok := strings.CutPrefix(q.Get("lower-store"), "local?")
	if !ok {
		t.Fatalf("the lower is %q", q.Get("lower-store"))
	}
	lq, _ := url.ParseQuery(lower)
	if lq.Get("real") != "/nix/store" || lq.Get("state") != dir+"/lower" || lq.Get("read-only") != "true" {
		t.Errorf("the lower is %v", lq)
	}
}

// A store no container holds, older than a launch takes to lock it, is
// removed, read-only paths and all; one a container holds, or one just
// made, is not.
func TestTheSweepRemovesOnlyStoresNoContainerHolds(t *testing.T) {
	h := newHarness(t)
	old := time.Now().Add(-time.Hour)
	gone := h.made("gone", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-left")
	held := h.made("held")
	young := h.made("young")
	for _, d := range []string{gone, held} {
		os.Chtimes(d, old, old)
	}
	fd, err := unix.Open(held+"/layers", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	Sweep(h.n.Session, &strings.Builder{})
	if _, err := os.Lstat(gone); err == nil {
		t.Error("a store no container holds is left")
	}
	for _, d := range []string{held, young} {
		if _, err := os.Lstat(d); err != nil {
			t.Errorf("%s was swept: %v", d, err)
		}
	}
}

// The upper's bytes are its blocks, and each inode is counted once.
func TestUsageCountsBlocksAndEachInodeOnce(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/a", make([]byte, 10000), 0o644)
	os.Link(dir+"/a", dir+"/b")
	f, _ := os.Create(dir + "/sparse")
	f.Truncate(1 << 30)
	f.Close()
	bytes, inodes, err := Usage(dir)
	if err != nil {
		t.Fatal(err)
	}
	if inodes != 3 {
		t.Errorf("%d inodes", inodes)
	}
	if bytes < 10000 || bytes > 1<<20 {
		t.Errorf("%d bytes", bytes)
	}
}

// What the store looks at of the host's is rooted on the host: every
// name its database holds that its upper does not, and the host holds
// valid, at most maxRoots of them, said when there are more; handed to
// nix as JSON by file, never as Nix source, its root one indirect link.
func TestRefreshRootsTheLowerPathsTheStoreLooksAt(t *testing.T) {
	h := newHarness(t)
	own := "dddddddddddddddddddddddddddddddd-built"
	dir := h.made("m1", own)
	h.k.Valid = []string{path('a', "glibc"), path('b', "bash"), "/nix/store/" + own, path('c', "gone"),
		"/nix/store/short-hash", "/etc/passwd", path('f', "x/y"), path('g', "gcc"), path('h', "hello")}
	h.k.Invalid = []string{path('c', "gone")}
	h.write()
	var said strings.Builder
	if err := Refresh(context.Background(), h.n, dir, &said); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dir + "/roots.json")
	if err != nil {
		t.Fatal(err)
	}
	var rooted []string
	json.Unmarshal(b, &rooted)
	if want := []string{path('a', "glibc"), path('b', "bash"), path('g', "gcc")}; !slices.Equal(rooted, want) {
		t.Errorf("rooted %q, not %q", rooted, want)
	}
	if !strings.Contains(said.String(), "looks at 4 of the host's paths, more than the 3 rooted; 1 are left unrooted") {
		t.Errorf("said %q", said.String())
	}
	if l, err := os.Readlink(dir + "/roots"); err != nil || !strings.HasSuffix(l, "roots-m1") {
		t.Errorf("the root is %q, %v", l, err)
	}
	sql := h.runs("sqlite3")
	if len(sql) != 1 {
		t.Fatalf("sqlite3 ran %d times", len(sql))
	}
	argv := strings.Join(sql[0].Argv, " ")
	for _, want := range []string{"-readonly", "-safe", ".dbconfig defensive on", ".dbconfig trusted_schema off", "PRAGMA query_only=1",
		"file:" + dir + "/state/db/db.sqlite?mode=ro", "SELECT path FROM ValidPaths"} {
		if !strings.Contains(argv, want) {
			t.Errorf("sqlite3 was not given %q: %s", want, argv)
		}
	}
	if len(sql[0].Env) != 0 {
		t.Errorf("sqlite3 had an environment: %q", sql[0].Env)
	}
	nix := h.runs("nix")
	if len(nix) != 1 {
		t.Fatalf("nix ran %d times", len(nix))
	}
	store := h.runs("nix-store")
	if last := store[len(store)-1].Argv; !slices.Equal(last[1:], []string{"--realise", path('r', "chase-nix-roots"), "--add-root", dir + "/roots", "--indirect"}) {
		t.Errorf("rooted as %q", last)
	}
	if !slices.Contains(nix[0].Argv, rootsExpr) || !slices.Contains(nix[0].Env, "CHASE_NIX_ROOTS="+dir+"/roots.json") || !slices.Contains(nix[0].Env, "NIX_REMOTE=daemon") {
		t.Errorf("nix ran as %q, %q", nix[0].Argv, nix[0].Env)
	}
	for _, a := range nix[0].Argv {
		if strings.Contains(a, "glibc") {
			t.Errorf("a name the session wrote is in nix's arguments: %q", a)
		}
	}
}

// A store with nothing of the host's to root has no root; a database that
// will not read is an error, and a database too large is not read at all.
func TestRefreshWithNothingToRootOrNothingReadable(t *testing.T) {
	h := newHarness(t)
	dir := h.made("m1")
	os.Symlink("/nowhere", dir+"/roots")
	if err := Refresh(context.Background(), h.n, dir, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir + "/roots"); err == nil {
		t.Error("a root is left with nothing to root")
	}
	h.k.SQLFail = true
	h.write()
	if err := Refresh(context.Background(), h.n, dir, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "malformed database schema") {
		t.Errorf("a database that will not read: %v", err)
	}
	h.k.SQLFail = false
	h.write()
	os.Truncate(dir+"/state/db/db.sqlite", maxDB+1)
	before := len(h.runs("sqlite3"))
	if err := Refresh(context.Background(), h.n, dir, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "more than a session's store is read at") {
		t.Errorf("a database too large: %v", err)
	}
	if len(h.runs("sqlite3")) != before {
		t.Error("a database too large was read")
	}
}

// The upper's names are promoted by name, but derivations and locks, as a
// unit of the user's own, through the host's daemon, with no build and
// keeping going past a name no cache has.
func TestPromotionIsByNameThroughAUnitOfTheUsers(t *testing.T) {
	h := newHarness(t)
	dir := h.made("m1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-shell.drv",
		"cccccccccccccccccccccccccccccccc-x.lock", ".links", "not-a-store-path")
	if err := Promote(context.Background(), h.n, "m1", dir, "/run/user/1000"); err != nil {
		t.Fatal(err)
	}
	runs := h.runs("systemd-run")
	if len(runs) != 1 {
		t.Fatalf("systemd-run ran %d times", len(runs))
	}
	argv := runs[0].Argv
	at := slices.Index(argv, "--")
	if at < 0 || !slices.Contains(argv[:at], "--unit=chase-promote-m1") || !slices.Contains(argv[:at], "--user") {
		t.Fatalf("systemd-run ran as %q", argv)
	}
	if want := []string{h.n.Session.NixStore, "--realise", "--keep-going", "--option", "max-jobs", "0", "--option", "substitute", "true",
		"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello"}; !slices.Equal(argv[at+1:], want) {
		t.Errorf("promoted as %q, not %q", argv[at+1:], want)
	}
	if !slices.Contains(runs[0].Env, "XDG_RUNTIME_DIR=/run/user/1000") {
		t.Errorf("systemd-run's environment: %q", runs[0].Env)
	}
}

// Nothing is promoted of an upper past the tier's bytes.
func TestAnUpperPastItsBytesIsNotPromoted(t *testing.T) {
	h := newHarness(t)
	dir := h.made("m1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-big")
	big := dir + "/layers/upper/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-big"
	os.Chmod(big, 0o755)
	os.WriteFile(big+"/blob", make([]byte, 2<<20), 0o444)
	if err := Promote(context.Background(), h.n, "m1", dir, "/run/user/1000"); err == nil || !strings.Contains(err.Error(), "more than the tier's") {
		t.Errorf("promoted: %v", err)
	}
	if h.runs("systemd-run") != nil {
		t.Error("systemd-run ran")
	}
}

// postStop promotes and removes the whole store, read-only paths and the
// root among it; run again, or for a session that had none, it is nothing.
func TestPostStopPromotesAndRemovesTheStore(t *testing.T) {
	h := newHarness(t)
	dir := h.made("m1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello")
	os.Symlink("/nowhere", dir+"/roots")
	for range 2 {
		if err := PostStop(context.Background(), h.n, "m1", "/run/user/1000", &strings.Builder{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(dir); err == nil {
		t.Error("the store is left")
	}
	if n := len(h.runs("systemd-run")); n != 1 {
		t.Errorf("promoted %d times", n)
	}
	h.n.Session.Promote = false
	dir = h.made("m2", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello")
	if err := PostStop(context.Background(), h.n, "m2", "/run/user/1000", &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if n := len(h.runs("systemd-run")); n != 1 {
		t.Errorf("promoted where the tier does not promote")
	}
}

// The watcher stops the session once its upper is past the tier's
// inodes, killing its leader and saying so; and roots what the store looks
// at as its database changes.
func TestTheWatcherRootsAndStopsASessionOverItsLimit(t *testing.T) {
	h := newHarness(t)
	dir := h.made("m1")
	h.k.Valid = []string{path('a', "glibc")}
	h.write()
	leader := exec.Command("sleep", "60")
	if err := leader.Start(); err != nil {
		t.Skip("no sleep to stand in for the leader")
	}
	done := make(chan error, 1)
	var said strings.Builder
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- Watch(ctx, h.n, "m1", leader.Process.Pid, &said) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Lstat(dir + "/roots"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing was rooted")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for i := range 101 {
		os.WriteFile(filepath.Join(dir, "layers/upper", "f"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)), nil, 0o644)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watcher did not stop the session")
	}
	err := leader.Wait()
	if ws, ok := leader.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Errorf("the leader ended %v", err)
	}
	if !strings.Contains(said.String(), "the session's nix store is over its limit") {
		t.Errorf("said %q", said.String())
	}
}
