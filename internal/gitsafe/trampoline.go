package gitsafe

import (
	"os"
	"runtime"
	"runtime/debug"
	"syscall"
	"unsafe"
)

// trampolineArg is the hidden first argument that makes the chase binary
// the step between Run and git: set the limit, and become git.
const trampolineArg = "__chase-gitsafe-exec"

// MaybeExec is the address-space limit's trampoline, and every binary that
// runs git through this package calls it first thing in main (a test binary,
// in TestMain). Invoked as `SELF __chase-gitsafe-exec GIT ARG...` it sets
// RLIMIT_AS and executes GIT in its own place, and never returns; invoked any
// other way it returns at once and does nothing.
//
// WHY A TRAMPOLINE. The shell ran `ulimit -v` in the subshell that then
// became git, so the limit was in place before git's first allocation. Go
// cannot set a limit on a child it starts -- os/exec has no rlimits, and
// prlimit on a started child races its first mapping -- so the child is
// this binary again, which limits itself and executes git: execve keeps the
// limit and drops every mapping the Go runtime made.
//
// WHY IT STILL WORKS WHEN GO IS ALREADY OVER THE LIMIT. Go reserves address
// space up front: a small Go binary on linux/amd64 has a VmSize of about
// 1.2 GB (1,227,208 kB measured, go1.26) before main runs, more than the
// 1 GiB given to git. setrlimit does not look at what is already mapped, so
// it succeeds, and only a new mapping after it would fail -- which would be
// the runtime's, and fatal. So nothing is allocated between the two calls:
// execve's arguments are built first, the collector is off, and execve is
// made as a raw system call. A limit as low as 64 MiB was measured to reach
// git the same way.
//
// A hard limit already lower than this one cannot be raised, and bounds git
// as well: failing to set it is not failing open, and git runs regardless,
// as `ulimit -v ... || true` let it.
func MaybeExec() {
	if len(os.Args) < 3 || os.Args[1] != trampolineArg {
		return
	}
	runtime.LockOSThread()
	// One P, and this goroutine holding it through both raw system calls,
	// which never give it up: no other goroutine runs between them, and no
	// idle P is left for the scheduler to start a thread for. Without this,
	// the runtime's own goroutines, parking on other threads just after
	// startup, woke a P and made a new thread for it -- a new mapping after
	// the limit, which is fatal: "fatal error: runtime: cannot allocate
	// memory" reached git's stderr, from a process that execve then replaced
	// anyway, and LsFiles, rightly, took any stderr for a sparse index. Seen
	// under load, once in a few hundred calls.
	runtime.GOMAXPROCS(1)
	debug.SetGCPercent(-1)
	path := os.Args[2]
	argv0, err := syscall.BytePtrFromString(path)
	if err != nil {
		os.Stderr.WriteString("chase: cannot run git: " + err.Error() + "\n")
		os.Exit(StatusCannot)
	}
	argv, err := syscall.SlicePtrFromStrings(os.Args[2:])
	if err != nil {
		os.Stderr.WriteString("chase: cannot run git: " + err.Error() + "\n")
		os.Exit(StatusCannot)
	}
	envv, err := syscall.SlicePtrFromStrings(os.Environ())
	if err != nil {
		os.Stderr.WriteString("chase: cannot run git: " + err.Error() + "\n")
		os.Exit(StatusCannot)
	}
	limit := syscall.Rlimit{Cur: AddressSpace, Max: AddressSpace}
	syscall.RawSyscall6(syscall.SYS_PRLIMIT64, 0, syscall.RLIMIT_AS, uintptr(unsafe.Pointer(&limit)), 0, 0, 0)
	_, _, errno := syscall.RawSyscall(syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(argv0)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envv[0])))
	// Only a failed execve gets here, still under the limit.
	os.Stderr.WriteString("chase: cannot run " + path + ": " + errno.Error() + "\n")
	if errno == syscall.ENOENT {
		os.Exit(StatusNotFound)
	}
	os.Exit(StatusCannot)
}
