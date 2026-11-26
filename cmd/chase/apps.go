package main

// The apps whose packages register commands of their own (internal/appcmd):
// importing one is what installs its commands, as `chase internal app`.
// Most apps have none, being data -- their operations and a module -- and
// need no line here.
import (
	_ "github.com/danielbodart/chase/internal/apps/claude"
	_ "github.com/danielbodart/chase/internal/apps/codex"
	_ "github.com/danielbodart/chase/internal/apps/ssh"
	_ "github.com/danielbodart/chase/internal/gcloud"
)
