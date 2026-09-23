# Someone else's code, forks included. No network but frisket, which allows
# only the names its apps add. GitHub is read-only and anonymous: clone and
# fetch work, and nothing the session reads can make it write.
{
  chase.tiers.strict = {
    egress = "frisket";
    # Nobody is asked on behalf of someone else's code: what is not a read is
    # refused, in every app, and so is what no operation names.
    writes = "refuse";
    guarded = "refuse";
    unmatched = "refuse";
    # flong's strict filter and nothing added: no ptrace, no io_uring, no
    # mount, no keyring. strace and gdb do not work here, on purpose.
    seccomp.tier = "strict";
    apps = {
      claude = { state = "isolated"; connectors = false; };
      codex.state = "isolated";
      git = { enable = true; anonymous = true; };
      github = { enable = true; anonymous = true; };
    };
  };
}
