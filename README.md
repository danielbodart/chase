# chase

Agent policy for [NixOS](https://nixos.org/): which sandbox a checkout gets,
which apps run inside it, and which credential each of those is given.

> A *chase* is the iron frame that locks a page of composed type together, so
> the whole forme can be lifted and printed as one. [flong](https://github.com/danielbodart/flong)
> casts the plate; [frisket](https://github.com/danielbodart/frisket) decides
> what the sheet is allowed to take; chase is what holds the page.

chase sits on flong and frisket and is known by neither. It holds no secrets
and names no machine: who the user is, which organisations are trusted, and
where a credential comes from all arrive as options. A project declares what it
needs by depending on chase — never on the configuration of the machine it is
being worked on.

The design, what was decided and what is still open, is in [PLAN.md](PLAN.md).

## Status

Early. The module it is being extracted from works; nothing here does yet.
