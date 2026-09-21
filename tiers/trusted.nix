# Our own code. Its own network namespace with outbound access, so the
# host's loopback is out of reach; frisket answers DNS, so every lookup is
# logged.
{
  chase.tiers.trusted = {
    egress = "direct";
    allow = [ "*" ];
    # A checkout's own envelope, once approved: its flake's files before
    # anything of it runs, and what its chase section says. PLAN.md, 17.
    envelope = true;
    apps = {
      claude = { state = "shared"; connectors = true; };
      codex.state = "shared";
      github.enable = true;
    };
  };
}
