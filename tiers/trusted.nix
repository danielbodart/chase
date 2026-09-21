# Our own code. Its own network namespace with outbound access, so the
# host's loopback is out of reach; frisket answers DNS, so every lookup is
# logged.
{
  chase.tiers.trusted = {
    egress = "direct";
    allow = [ "*" ];
    # OFF until an envelope can be evaluated without reaching anything: a
    # project's flake resolves its inputs before approval, and those can read
    # any of the user's files or fetch any URL. See PLAN.md, decision 17.
    envelope = false;
    apps = {
      claude = { state = "shared"; connectors = true; };
      codex.state = "shared";
      github.enable = true;
    };
  };
}
