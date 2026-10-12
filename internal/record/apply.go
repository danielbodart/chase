package record

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/danielbodart/frisket/projpolicy"

	"github.com/danielbodart/chase/internal/grant"
)

// MERGING A PROPOSAL into the checkout's chase.json: each entry its
// proposal.json proposes is put where it goes in the file, which is then
// written in its canonical form and must be a chase.json chase reads, or
// nothing is written. A person may have edited the proposal: what is in
// its `propose` is what is merged, and nothing else of it.
//
// An entry already there is left. An answer of another word for the same
// operation, or call, is replaced, and a command in another of the same
// machine's lists moved: a name in two lists is one the file refuses. A
// name on the local network the file has already is given the ports it
// lacked.

// Change is what a merge did with one entry: added it, moved it from
// another answer (From), widened the entry already there (Widened, a name
// on the local network given ports it lacked), or found it there already
// (Kept).
type Change struct {
	Path    []string
	Value   string
	From    string
	Widened bool
	Kept    bool
}

// sshLists are a machine's lists in chase.json.
var sshLists = []string{"allow", "ask", "refuse"}

// item is one entry of a proposal's `propose`: where it goes, its key
// there or "" in a list, and its value.
type item struct {
	path  []string
	key   string
	value any
}

// items is every entry of a proposal's `propose`, or why it is not a
// proposal: anything but the entries a recording proposes is refused, so
// an apply never writes to a file what a proposal could not have held.
func items(proposal []byte) ([]item, error) {
	v, err := projpolicy.Decode(proposal)
	if err != nil {
		return nil, err
	}
	root, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("a proposal is an object")
	}
	propose, ok := root["propose"].(map[string]any)
	if !ok {
		return nil, errors.New("a proposal's propose is an object of what it adds")
	}
	var out []item
	object := func(v any, at ...string) (map[string]any, error) {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s is not an object", strings.Join(at, "."))
		}
		return m, nil
	}
	only := func(m map[string]any, at string, keys ...string) error {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if !slices.Contains(keys, k) {
				return fmt.Errorf("%s.%s: a proposal holds only %s there", at, k, strings.Join(keys, ", "))
			}
		}
		return nil
	}
	if err := only(propose, "propose", "frisket", "flong", "chase"); err != nil {
		return nil, err
	}
	if f, ok := propose["frisket"]; ok {
		fm, err := object(f, "frisket")
		if err != nil {
			return nil, err
		}
		if err := only(fm, "frisket", "allow", "lan", "routes"); err != nil {
			return nil, err
		}
		if a, ok := fm["allow"]; ok {
			am, err := object(a, "frisket", "allow")
			if err != nil {
				return nil, err
			}
			for _, k := range slices.Sorted(maps.Keys(am)) {
				if am[k] != true {
					return nil, fmt.Errorf("frisket.allow.%s: a name is allowed with true", k)
				}
				out = append(out, item{[]string{"frisket", "allow"}, k, true})
			}
		}
		if l, ok := fm["lan"]; ok {
			lm, err := object(l, "frisket", "lan")
			if err != nil {
				return nil, err
			}
			for _, k := range slices.Sorted(maps.Keys(lm)) {
				h, err := object(lm[k], "frisket", "lan", k)
				if err != nil {
					return nil, err
				}
				if err := only(h, "frisket.lan."+k, "ports"); err != nil {
					return nil, err
				}
				out = append(out, item{[]string{"frisket", "lan"}, k, h})
			}
		}
		if r, ok := fm["routes"]; ok {
			rm, err := object(r, "frisket", "routes")
			if err != nil {
				return nil, err
			}
			for _, route := range slices.Sorted(maps.Keys(rm)) {
				one, err := object(rm[route], "frisket", "routes", route)
				if err != nil {
					return nil, err
				}
				if err := only(one, "frisket.routes."+route, "operations"); err != nil {
					return nil, err
				}
				ops, err := object(one["operations"], "frisket", "routes", route, "operations")
				if err != nil {
					return nil, err
				}
				for _, k := range slices.Sorted(maps.Keys(ops)) {
					if a, ok := ops[k].(string); !ok || rank(a) < 0 {
						return nil, fmt.Errorf("frisket.routes.%s.operations.%s: not allow, ask or refuse", route, k)
					}
					out = append(out, item{[]string{"frisket", "routes", route, "operations"}, k, ops[k]})
				}
			}
		}
	}
	if f, ok := propose["flong"]; ok {
		fm, err := object(f, "flong")
		if err != nil {
			return nil, err
		}
		if err := only(fm, "flong", "seccomp"); err != nil {
			return nil, err
		}
		sm, err := object(fm["seccomp"], "flong", "seccomp")
		if err != nil {
			return nil, err
		}
		if err := only(sm, "flong.seccomp", "syscalls"); err != nil {
			return nil, err
		}
		calls, err := object(sm["syscalls"], "flong", "seccomp", "syscalls")
		if err != nil {
			return nil, err
		}
		for _, k := range slices.Sorted(maps.Keys(calls)) {
			out = append(out, item{[]string{"flong", "seccomp", "syscalls"}, k, calls[k]})
		}
	}
	if c, ok := propose["chase"]; ok {
		cm, err := object(c, "chase")
		if err != nil {
			return nil, err
		}
		if err := only(cm, "chase", "apps"); err != nil {
			return nil, err
		}
		am, err := object(cm["apps"], "chase", "apps")
		if err != nil {
			return nil, err
		}
		if err := only(am, "chase.apps", "ssh"); err != nil {
			return nil, err
		}
		sm, err := object(am["ssh"], "chase", "apps", "ssh")
		if err != nil {
			return nil, err
		}
		if err := only(sm, "chase.apps.ssh", "hosts"); err != nil {
			return nil, err
		}
		hosts, err := object(sm["hosts"], "chase", "apps", "ssh", "hosts")
		if err != nil {
			return nil, err
		}
		for _, h := range slices.Sorted(maps.Keys(hosts)) {
			lists, err := object(hosts[h], "chase", "apps", "ssh", "hosts", h)
			if err != nil {
				return nil, err
			}
			if err := only(lists, "chase.apps.ssh.hosts."+h, sshLists...); err != nil {
				return nil, err
			}
			for _, l := range sshLists {
				entries, ok := lists[l]
				if !ok {
					continue
				}
				a, ok := entries.([]any)
				if !ok {
					return nil, fmt.Errorf("chase.apps.ssh.hosts.%s.%s is not a list", h, l)
				}
				for _, e := range a {
					if _, ok := e.(string); !ok {
						return nil, fmt.Errorf("chase.apps.ssh.hosts.%s.%s: %v is not an id or a pattern", h, l, e)
					}
					out = append(out, item{[]string{"chase", "apps", "ssh", "hosts", h, l}, "", e})
				}
			}
		}
	}
	return out, nil
}

// object is the object at path in v, made where it is not there.
func objectAt(v map[string]any, path []string) map[string]any {
	m := v
	for _, k := range path {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	return m
}

// Merge is current -- a checkout's chase.json, or nil for none -- with
// each entry of proposal in place, in its canonical form, and what was
// done with each entry. What it returns is a chase.json ParseDoc reads, or
// an error and nothing.
func Merge(current, proposal []byte) ([]byte, []Change, error) {
	its, err := items(proposal)
	if err != nil {
		return nil, nil, fmt.Errorf("the proposal: %w", err)
	}
	var doc map[string]any
	if current == nil {
		doc = map[string]any{"version": 2}
	} else {
		v, err := projpolicy.Decode(current)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", grant.FileName, err)
		}
		var ok bool
		if doc, ok = v.(map[string]any); !ok {
			return nil, nil, fmt.Errorf("%s is not an object", grant.FileName)
		}
	}
	var changes []Change
	for _, it := range its {
		c := Change{Path: it.path, Value: show(it.key, it.value)}
		if it.key == "" {
			// A machine's list: the machine must be the file's own.
			host := it.path[:len(it.path)-1]
			if _, ok := walk(doc, host); !ok {
				return nil, nil, fmt.Errorf("%s names no machine %s: only the file's own machines take lists", grant.FileName, host[len(host)-1])
			}
			lists := objectAt(doc, host)
			list := it.path[len(it.path)-1]
			for _, other := range sshLists {
				a, _ := lists[other].([]any)
				i := slices.Index(a, it.value)
				if i < 0 {
					continue
				}
				if other == list {
					c.Kept = true
					break
				}
				c.From = other
				lists[other] = slices.Delete(a, i, i+1)
				if len(lists[other].([]any)) == 0 {
					delete(lists, other)
				}
			}
			if !c.Kept {
				a, _ := lists[list].([]any)
				lists[list] = append(a, it.value)
			}
			changes = append(changes, c)
			continue
		}
		m := objectAt(doc, it.path)
		was, there := m[it.key]
		switch {
		case !there:
			m[it.key] = it.value
		case slices.Equal(it.path, []string{"frisket", "lan"}):
			c.Widened, c.Kept = widen(m, it.key, it.value)
		case fmt.Sprint(was) == fmt.Sprint(it.value):
			c.Kept = true
		default:
			c.From = fmt.Sprint(was)
			m[it.key] = it.value
		}
		changes = append(changes, c)
	}
	out, err := projpolicy.Encode(doc)
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := grant.ParseDoc(out); err != nil {
		return nil, nil, fmt.Errorf("with the proposal, %s would not be one chase reads: %w", grant.FileName, err)
	}
	return out, changes, nil
}

// widen gives the lan entry name in m the ports v has that it lacks: an
// entry with no ports is every port already.
func widen(m map[string]any, name string, v any) (widened, kept bool) {
	have, _ := m[name].(map[string]any)
	add, _ := v.(map[string]any)
	hp, _ := have["ports"].([]any)
	ap, _ := add["ports"].([]any)
	if have == nil || len(hp) == 0 {
		return false, true
	}
	ports := slices.Clone(hp)
	for _, p := range ap {
		if !slices.ContainsFunc(ports, func(q any) bool { return fmt.Sprint(q) == fmt.Sprint(p) }) {
			ports = append(ports, p)
		}
	}
	if len(ports) == len(hp) {
		return false, true
	}
	slices.SortFunc(ports, func(a, b any) int {
		x, _ := strconv.Atoi(fmt.Sprint(a))
		y, _ := strconv.Atoi(fmt.Sprint(b))
		return x - y
	})
	have["ports"] = ports
	return true, false
}

// walk is the value at path in v, and whether there is one.
func walk(v any, path []string) (any, bool) {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[k]; !ok {
			return nil, false
		}
	}
	return v, true
}

// show is an entry as a person reads it in what apply says.
func show(key string, v any) string {
	if key == "" {
		return fmt.Sprintf("%q", v)
	}
	switch v := v.(type) {
	case bool:
		return fmt.Sprintf("%q", key)
	case string:
		return fmt.Sprintf("%q: %q", key, v)
	}
	return fmt.Sprintf("%q", key)
}
