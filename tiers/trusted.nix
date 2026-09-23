# Our own code. Its own network namespace with outbound access, so the
# host's loopback is out of reach; frisket answers DNS, so every lookup is
# logged.
{
  chase.tiers.trusted = {
    egress = "direct";
    allow = [ "*" ];
    # strace and gdb, on our own code. ptrace reaches no further than the
    # session's own processes.
    seccomp.debug = true;
    # A checkout's own envelope, once approved: its flake's files before
    # anything of it runs, and what its chase section says. PLAN.md, 17.
    envelope = true;
    # A dev server started in a session is reached at the same port on the
    # host, for as long as it listens.
    forwardPorts = "auto";
    apps = {
      claude = { state = "shared"; connectors = true; };
      codex.state = "shared";
      git.enable = true;
      github.enable = true;
    };
  };
}
