// Package appcmd is how an app gives chase commands of its own, run outside
// a launch: what the module's units, activation and the system's build run
// for it, as `chase internal app NAME COMMAND [ARG...]`. An app's package
// registers its commands, and the section of the module's configuration
// they read, when it is loaded; chase's main knows no app by name.
//
// A command reads its section through Section, decoded strictly into the
// app's own type, so an app's package needs nothing of package config,
// which imports the apps' types and would otherwise be imported back.
package appcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// Command is one of an app's commands.
type Command struct {
	// Args is what follows the command's name, for usage: "" for none.
	Args string
	// Help is a line on what runs it and what it does.
	Help string
	// Run runs it: section is the app's section of the configuration,
	// args the command's own arguments. It returns the process's status.
	Run func(ctx context.Context, section Section, args []string, stderr io.Writer) int
}

// Section decodes the app's section of the module's configuration into v,
// strictly, and says whether the module configures one at all.
type Section func(v any) (bool, error)

type app struct {
	key      string
	commands map[string]Command
}

var apps = map[string]app{}

// Register gives app its commands, which read the configuration's section
// at key, a dotted path ("grant.ssh"). Called from the app package's init;
// a name registered twice is a programming error.
func Register(name, key string, commands map[string]Command) {
	if _, ok := apps[name]; ok {
		panic("appcmd: " + name + " is registered twice")
	}
	apps[name] = app{key: key, commands: commands}
}

// Run is `chase internal app NAME COMMAND [ARG...]` over the configuration
// file's bytes: the app's command with its section, or a usage on stderr
// and 2.
func Run(ctx context.Context, config []byte, args []string, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprint(stderr, Usage())
		return 2
	}
	a, ok := apps[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "chase internal app: no app %q\n%s", args[0], Usage())
		return 2
	}
	c, ok := a.commands[args[1]]
	if !ok {
		fmt.Fprintf(stderr, "chase internal app %s: no command %q\n%s", args[0], args[1], Usage())
		return 2
	}
	section := func(v any) (bool, error) {
		raw, err := at(config, a.key)
		if err != nil || raw == nil {
			return false, err
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return true, fmt.Errorf("%s: %w", a.key, err)
		}
		return true, nil
	}
	return c.Run(ctx, section, args[2:], stderr)
}

// at is the JSON value at the dotted path key in b, or nil where there is
// none or it is null.
func at(b []byte, key string) (json.RawMessage, error) {
	raw := json.RawMessage(b)
	for _, k := range strings.Split(key, ".") {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, errors.New("the configuration is not a JSON object at " + key)
		}
		v, ok := m[k]
		if !ok || string(v) == "null" {
			return nil, nil
		}
		raw = v
	}
	return raw, nil
}

// Usage is every app's commands, as `chase internal app` lists them.
func Usage() string {
	var b strings.Builder
	b.WriteString("usage: chase internal app NAME COMMAND [ARG...]\n")
	for _, name := range slices.Sorted(maps.Keys(apps)) {
		cs := apps[name].commands
		for _, c := range slices.Sorted(maps.Keys(cs)) {
			line := name + " " + c
			if cs[c].Args != "" {
				line += " " + cs[c].Args
			}
			fmt.Fprintf(&b, "  %-30s %s\n", line, cs[c].Help)
		}
	}
	return b.String()
}

// Errorf is a command's failure said on stderr as `chase internal app NAME
// COMMAND: ...`, and status 1, for a Run that has an error to say.
func Errorf(stderr io.Writer, name, command string, err error) int {
	fmt.Fprintf(stderr, "chase internal app %s %s: %v\n", name, command, err)
	return 1
}

// Configured is section decoded into v, or the error a command returns
// when the module configures no section for it.
func Configured(section Section, name string, v any) error {
	ok, err := section(v)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("the module configures no " + name)
	}
	return nil
}
