# Our own code. Its own network namespace with outbound access, so the
# host's loopback is out of reach; frisket answers DNS, so every lookup is
# logged.
{
  agents.tiers.trusted = {
    egress = "direct";
    allow = [ "*" ];
    apps = {
      claude = { state = "shared"; connectors = true; };
      codex.state = "shared";
      dragoman.enable = true;
      github.enable = true;
      audio.enable = true;
      mise.enable = true;
    };
  };
}
