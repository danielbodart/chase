# How an app's operations are answered in a tier (PLAN.md, decision 18).
#
# chase-generate operations (../internal/generate) says what each operation IS
# -- read, write or guarded -- and nothing about what is done with it. That is
# said here, from the tier's settings and the app's own, the same way for
# every app, as a version 2 route's class answers, which frisket applies
# at each request:
#
#   read     allowed
#   write    the app's `writes`, which is the tier's unless the app says
#   guarded  the app's `guarded`, likewise
#
# and what no operation matches, the app's `unmatched`. An app a tier has
# without `authenticated` has no credential and no one to ask on its behalf:
# all three are refused, whatever the tier says.
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

  # What an app in a tier answers with. One that is not `authenticated` has
  # no credential and no one to ask on its behalf: all three are refused,
  # whatever the tier says. An app with no `authenticated` -- one whose
  # credential is only ever a project's -- answers as the tier and the app
  # say.
  settings = app:
    if !(app.authenticated or true)
    then lib.genAttrs names (_: "refuse") // { anonymous = true; }
    else answers app;

  # The app's three as it says them, for a route a project's own credential
  # may stand behind whether or not the tier has one.
  answers = app: lib.getAttrs names app;

  # A version 1 allowlist name as frisket's version 2 host grammar has it:
  # "*" is every name, "**", and "*.suffix" every name below suffix,
  # "**.suffix". A tier's `allow` keeps version 1's words.
  hostKey = n:
    if n == "*" then "**"
    else if lib.hasPrefix "*." n then "*${n}"
    else n;

  # A version 2 allowlist of names, each a key to true.
  allowOf = names: lib.genAttrs (map hostKey names) (_: true);

  # A generated rule's key in a version 2 route's paths: its methods and
  # its path, or every path below its prefix.
  endpoint = r: lib.concatStringsSep "," r.methods + " "
    + (if r ? path then r.path else lib.removeSuffix "/" r.prefix + "/**");

  # The route's answers by class, the app's; and for an app with no
  # credential, which has nobody to ask on its behalf and refuses every
  # class, a ceiling of the same, so that a project's file answers none of
  # its requests more leniently (PLAN.md, decision 18).
  answering = s: lib.getAttrs names s
    // lib.optionalAttrs (s.anonymous or false) { ceiling = lib.genAttrs names (_: "refuse"); };

  # What an app's generated operations make of a version 2 route: what each
  # request IS -- `paths`, and GraphQL's fields -- which frisket answers by
  # its class as the app says, a read allowed (PLAN.md, decision 18).
  # GraphQL's operations are not paths: `graphql` has them, each field by
  # its name, a query by `query`.
  route = s: operations:
    let
      rest = lib.filter (r: !(r ? graphql)) operations;
      gql = lib.filter (r: r ? graphql) operations;
      encoded = lib.filter (r: r.encodedSlashes or false) rest;
      of = path: lib.filter (r: r.graphql == path) gql;
      fields = kind: path: lib.listToAttrs (map (r: lib.nameValuePair r.${kind} { inherit (r) operation; })
        (lib.filter (r: r ? ${kind}) (of path)));
      endpointOf = path: lib.filterAttrs (_: v: v != { }) {
        mutations = fields "mutation" path;
        subscriptions = fields "subscription" path;
      } // lib.optionalAttrs (lib.any (r: r.query or false) (of path)) {
        query = { inherit (lib.findFirst (r: r.query or false) null (of path)) operation; };
      };
    in
    answering s
    // lib.optionalAttrs (rest != [ ]) {
      paths = lib.listToAttrs (map (r: lib.nameValuePair (endpoint r)
        ({ inherit (r) operation; } // lib.optionalAttrs (r ? docker) { inherit (r) docker; })) rest);
    }
    // lib.optionalAttrs (encoded != [ ]) { encodedSlashes = lib.genAttrs (map endpoint encoded) (_: true); }
    // lib.optionalAttrs (gql != [ ]) {
      graphql = lib.genAttrs (lib.unique (map (r: r.graphql) gql)) endpointOf;
    };
}
