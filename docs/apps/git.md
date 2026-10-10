# git

git over HTTPS to github.com, and what github.com serves beside it: release
downloads, archives, Git LFS. `git@github.com:` remotes are rewritten to
HTTPS, so no SSH key is needed. frisket adds the token as Basic auth's
password. A fetch is a read; a push is a write, asked about once with the
refs it updates. See [../github.md](../github.md).

| `chase.apps.git.…` | Default | |
|---|---|---|
| `package` | `pkgs.git` | |
| `credentialFile` | `chase.apps.github.credentialFile` | A GitHub token. |
| `config` | `~/.gitconfig`, `~/.config/git` | Your git configuration, bound read-only when `authenticated`. Each must exist. |

| `chase.tiers.<name>.apps.git.…` | Default | |
|---|---|---|
| `enable` | `false` | Without `authenticated`: public clones and fetches, no push. |
| `authenticated` | `false` | Use the token, and bind `config`. |
| `sign` | `authenticated` | Sign commits through frisket's agent. |
| `writes`, `guarded`, `unmatched` | the tier's | `writes` answers a push. |

```nix
chase.tiers.trusted.apps.git = { enable = true; authenticated = true; writes = "allow"; };
```

A tier that signs has `SSH_AUTH_SOCK=/run/frisket-sign/<tier>/agent`:
frisket's agent, which lists `chase.apps.ssh.agentSocket`'s keys and signs
only git's SSHSIGs with them. Turn signing on in your own git config
(`gpg.format = ssh`, `user.signingkey`, `commit.gpgsign`), bound in by
`authenticated`.

Grant: `apps.git.allow`, `ask` and `refuse`, e.g. `["git-receive-pack"]` for
pushes.
