# Someone else's code, forks included. No network but frisket, which allows
# only the names its apps add. GitHub is read-only and anonymous: clone and
# fetch work, and nothing the session reads can make it write.
#
# No uid namespace yet: privateUsers breaks the host-owned bind mounts.
{
  agents.tiers.strict = {
    egress = "frisket";
    apps = {
      claude = { state = "isolated"; connectors = false; };
      codex.state = "isolated";
      github = { enable = true; anonymous = true; };
    };
  };
}
