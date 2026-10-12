# docker

The Docker CLI and Compose, against your rootless daemon at
`/run/user/<uid>/docker.sock` (NixOS's `virtualisation.docker.rootless`).
frisket admits only operations on the project's own containers, volumes and
networks, and the images its grant names; no bind mounts, privileges or host
namespaces. Nothing asks. See [../docker.md](../docker.md).

| `chase.apps.docker.…` | Default | |
|---|---|---|
| `package` | `pkgs.docker-client` | |

| `chase.tiers.<name>.apps.docker.…` | Default | |
|---|---|---|
| `enable` | `false` | Only in a tier with `grants = true` and `egress = "direct"`. |
| `package` | the machine's | |

```nix
chase.tiers.trusted = { egress = "direct"; grants = true; apps.docker.enable = true; };
```

In the project's `chase.json`: its images, as `docker pull` shortens each,
with a tag or digest; the host ports its containers publish, 1024–65535;
and the project its `origin` names, which `chase sign` writes and a launch
holds the file to:

```json
"chase": {"apps": {"docker": {"images": {"postgres:18": true}, "ports": {"64320": true}, "project": "owner/repo"}}}
```

The project is the checkout's `origin`, and its ports are published at the
project's own address, as its dev servers are
([Project addresses](../../README.md#project-addresses)); a session reaches
them as `localhost` too. The session is given `CHASE_PROJECT`,
`CHASE_PROJECT_ADDRESS`, `CHASE_PROJECT_NAMES` and `CHASE_DOCKER_PORTS`.
`chase docker [DIR]` shows them.
