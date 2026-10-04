# Three tiers, as a machine might declare them: `host` for work a container
# cannot do, `trusted` for your own code, `strict` for everybody else's. chase
# ships none of these -- they are an example, and the baseline its checks
# evaluate against -- and nothing in chase knows their names.
#
# How far each predicate is believed is written here, not in chase. A path is
# the one signal a checkout cannot forge, so it alone may run something bare.
# A remote, an owner and a first commit's author are strings any checkout can
# claim, so they only raise a checkout as far as a sandbox, or lower one.
{
  chase = {
    # First to last; the first tier with a rule that holds wins.
    order = [ "host" "strict" "trusted" ];
    # Whatever no rule holds for, and whatever the selector cannot sort.
    fallback = "strict";

    # No container: real sudo, /dev/input, KVM, the network namespaces
    # themselves. Placed by path, and by a remote only where the path agrees.
    tiers.host = {
      bare = true;
      match = [
        # Exactly the home directory, never beneath it.
        { paths = [ "/home/alice" ]; }
        { checkouts."alice/nix-config" = "/home/alice/Projects/nix-config"; }
      ];
    };

    # Someone else's code, forks included. No network but frisket, which
    # allows only the names its apps add; nobody is asked on its behalf.
    tiers.strict = {
      match = [
        # A repository you do not trust, wherever it is. And the host's
        # repository anywhere but where it lives: a remote claiming to be it
        # from elsewhere is what a spoofed one looks like, so it is kept from
        # falling through to `trusted`'s owner.
        { repos = [ "alice/something-i-do-not-trust" "alice/nix-config" ]; }
      ];
      egress = "frisket";
      writes = "refuse";
      guarded = "refuse";
      unmatched = "refuse";
      # flong's strict filter and nothing added: no ptrace, no io_uring.
      seccomp.tier = "strict";
      apps = {
        # Their settings, and this workspace's transcripts and threads.
        claude = { enable = true; scope = "workspace"; };
        codex = { enable = true; scope = "workspace"; };
        # No credential: public clones, fetches and reads, and nothing that
        # writes.
        git.enable = true;
        github.enable = true;
      };
    };

    # Your own code: an owner of yours, and a first commit you wrote -- a
    # fork's is upstream's. And a fork you work on anyway, by remote and path.
    tiers.trusted = {
      match = [
        { owners = [ "alice" "her-employer" ]; rootAuthorDomains = [ "example.com" ]; }
        { checkouts."someone/a-fork-we-work-on" = "/home/alice/Projects/a-fork-we-work-on"; }
      ];
      egress = "direct";
      allow = [ "*" ];
      # strace and gdb, on your own code.
      seccomp.debug = true;
      # A checkout's own grant, once approved.
      grants = true;
      # A dev server started in a session is reached at the same port on the
      # host, for as long as it listens.
      forwardPorts = "auto";
      # What its tools download, kept for every checkout in the tier.
      caches = "tier";
      apps = {
        # Your own code: no trust dialog to answer for each checkout.
        claude = { enable = true; scope = "host"; connectors = true; trust = true; };
        codex = { enable = true; scope = "host"; trust = true; };
        git = { enable = true; authenticated = true; };
        github = { enable = true; authenticated = true; };
        # The checkout's devShell, where its grant turns it on with
        # "apps": {"nix": {"devShell": true}}: your own flake, realised
        # before the session starts and given to it as nix develop would.
        # One that cannot be realised refuses the launch.
        nix.enable = true;
      };
    };
  };
}
