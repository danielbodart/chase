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

Grant:

```jsonc
"docker": {
  "images": ["postgres:18"],   // as `docker pull` shortens it, with a tag or digest
  "ports": [64320],            // host ports its containers publish, 1024–65535
}
```

The project is the checkout's `origin`. It has its own loopback address
(`example/shop` is `127.101.170.171`) and names (`shop.internal`,
`shop.example.internal`); its ports are published there, and a session
reaches them as `localhost` too. `chase docker [DIR]` shows them.
