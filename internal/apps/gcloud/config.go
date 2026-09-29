package gcloud

// Config is what the NixOS module decides and the prepare step reads: what
// apps/gcloud.nix spliced into chase-gcloud-prepare's text, and its stop's.
type Config struct {
	// Tiers is every tier that has Google Cloud -- not bare, with
	// apps.gcloud.enable -- by name. A tier not here has none: a binding in
	// it is ignored, and said to be.
	Tiers map[string]Tier `json:"tiers"`
	// Catalogue is apps/gcloud in the store: index.json, whose keys are
	// every API a name may be, and apis/<api>.json, each API's generated
	// rules (docs/gcloud.md, decision 8). Read at launch, not embedded: it
	// is 11 MB the module already has, and its table is reviewed there.
	Catalogue string `json:"catalogue"`
	// Every is every method a rule may name, lib/operations.nix's `every`:
	// the methods of the catch-all an unmatched "allow" adds, and of the
	// refusal of the mtls hosts.
	Every []string `json:"every"`
	// Placeholder is chase.placeholder, what a session holds in the token's
	// place.
	Placeholder string `json:"placeholder"`
	// RuntimeDir is the user's runtime directory, /run/user/<uid>: the
	// XDG_RUNTIME_DIR systemctl --user needs to find the user's manager,
	// which postStop's environment does not have (measured), and where a
	// session's own directory is, RuntimeDir/chase/<machine>.
	RuntimeDir string `json:"runtimeDir"`
	// Systemctl is the systemctl to start and stop the renewer with:
	// config.systemd.package's.
	Systemctl string `json:"systemctl"`
	// TokenURL is where the first token's grant is posted. Empty is
	// Google's; only a check sets it.
	TokenURL string `json:"tokenURL,omitempty"`
}

// Tier is how a tier answers Google's operations -- ops.settings of its
// apps.gcloud, "allow", "ask" or "refuse" each, all three "refuse" for an
// anonymous app -- and the APIs it carries (PLAN.md, decision 18).
type Tier struct {
	// Writes answers an operation Google's descriptions call a write.
	Writes string `json:"writes"`
	// Guarded answers a guarded one: what cannot be taken back, widens who
	// can reach something, or returns a credential.
	Guarded string `json:"guarded"`
	// Unmatched answers what no rule matches: "allow" adds a catch-all rule,
	// and anything else is frisket's own unmatched, "ask" or "refuse".
	Unmatched string `json:"unmatched"`
	// APIs are the APIs the tier carries unless a project adds or removes
	// one, by Discovery name. The module has refused a name not in the
	// catalogue.
	APIs []string `json:"apis"`
}
