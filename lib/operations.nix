# How an app's operations are answered in a tier (PLAN.md, decision 18).
#
# ../scripts/operations.sh says what each operation IS -- read, write or
# guarded -- and nothing about what is done with it. That is said here, from
# the tier's settings and the app's own, the same way for every app:
#
#   read     allowed
#   write    the app's `writes`, which is the tier's unless the app says
#   guarded  the app's `guarded`, likewise
#
# and what no operation matches, the app's `unmatched`. An anonymous app has
# no credential and no one to ask on its behalf: all three are refused,
# whatever the tier says.
{ lib }:

let
  inherit (lib) mkOption types;
  answer = types.enum [ "allow" "ask" "refuse" ];
  every = [ "GET" "HEAD" "POST" "PUT" "PATCH" "DELETE" ];
  names = [ "writes" "guarded" "unmatched" ];
in
rec {
  inherit answer every;

  # The tier's three, each the default for every app in it.
  tierOptions = {
    writes = mkOption {
      type = answer;
      default = "ask";
      description = ''
        What a write is answered with, for every app in this tier that does
        not say otherwise: an operation that changes something, or a read
        that mints a credential.
      '';
    };
    guarded = mkOption {
      type = answer;
      default = "refuse";
      description = ''
        What a guarded operation is answered with, for every app in this tier
        that does not say otherwise: one that cannot be taken back, or that
        widens who can reach something -- a deletion, a transfer, a
        repository made public, a collaborator, key or secret added.
      '';
    };
    unmatched = mkOption {
      type = answer;
      default = "ask";
      description = ''
        What a request no operation matches is answered with, for every app
        in this tier that does not say otherwise. Asked by default: when in
        doubt, a person decides.
      '';
    };
  };

  # An app's three, each the tier's unless set. `tier` is the tier's config.
  appOptions = tier: lib.genAttrs names (n: mkOption {
    type = answer;
    default = tier.${n};
    defaultText = lib.literalExpression "the tier's `${n}`";
    description = "This app's `${n}`, in place of the tier's.";
  });

  # What an app in a tier answers with.
  settings = app:
    if app.anonymous or false
    then lib.genAttrs names (_: "refuse")
    else lib.getAttrs names app;

  outcome = a: { allow = { }; ask = { ask = true; }; refuse = { refuse = true; }; }.${a};

  # One generated operation as a frisket rule.
  rule = s: r: r // outcome ({
    read = "allow";
    write = s.writes;
    guarded = s.guarded;
  }.${r.operation.class});

  # Every operation as a rule, and -- where what matches nothing is allowed --
  # one more that matches everything and is less specific than any of them.
  # GraphQL's operations are not paths: `graphql` has them.
  paths = s: operations:
    map (rule s) (lib.filter (r: !(r ? graphql)) operations)
    ++ lib.optional (s.unmatched == "allow") { methods = every; prefix = "/"; };

  # frisket's GraphQL endpoints: each one's query, and its mutations and
  # subscriptions by field, answered as any operation is, the strictest in a
  # request deciding. A field no operation names is the app's `unmatched`;
  # what frisket cannot see is asked about where that allows.
  graphql = s: operations:
    let
      of = path: lib.filter (r: r.graphql or null == path) operations;
      field = kind: r: { field = r.${kind}; } // removeAttrs (rule s r) [ "graphql" kind ];
      fields = kind: path: map (field kind) (lib.filter (r: r ? ${kind}) (of path));
      endpoint = path: {
        inherit path;
        inherit (s) unmatched;
        mutations = fields "mutation" path;
        subscriptions = fields "subscription" path;
      } // lib.optionalAttrs (lib.any (r: r.query or false) (of path)) {
        query = removeAttrs (rule s (lib.findFirst (r: r.query or false) null (of path))) [ "graphql" "query" ];
      };
    in
    map endpoint (lib.unique (map (r: r.graphql) (lib.filter (r: r ? graphql) operations)));

  # frisket's own `unmatched`: an allowed one is the rule above.
  unmatched = s: if s.unmatched == "ask" then "ask" else "refuse";
}
