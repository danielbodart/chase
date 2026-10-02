package ssh

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// WHAT A GRANT MAY SAY OF A MACHINE, held to what frisket loads, each
// refusal naming the field it is about.
func TestWhatAGrantMayNameForAMachine(t *testing.T) {
	key, other := hostKey(t, "server"), hostKey(t, "other")
	host := func(extra string) string {
		return fmt.Sprintf(`{"hosts": {"server": %s}}`, merge(t, `{"address": "192.168.1.10", "user": "ops", "hostKeys": [%q]}`, key, extra))
	}
	for _, tc := range []struct {
		name, binding, said string
	}{
		{"a name with a capital", `{"hosts": {"Server": {}}}`, `apps.ssh.hosts.Server: "Server" is not a host's name`},
		{"a name that is an address", `{"hosts": {"10.0.0.1": {}}}`, "is an address"},
		{"a name for an address", host(`{"address": "server.lan"}`), "apps.ssh.hosts.server.address: address \"server.lan\": a literal IP"},
		{"no address", host(`{"address": ""}`), "apps.ssh.hosts.server.address"},
		{"port 0", host(`{"address": "10.0.0.1:0"}`), "port 0"},
		{"loopback", host(`{"address": "127.0.0.1"}`), "loopback"},
		{"link-local", host(`{"address": "169.254.169.254"}`), "link-local"},
		{"v6 link-local", host(`{"address": "[fe80::1]:22"}`), "link-local"},
		{"multicast", host(`{"address": "224.0.0.1"}`), "multicast"},
		{"unspecified", host(`{"address": "0.0.0.0"}`), "unspecified"},
		{"a v4 address as v6", host(`{"address": "::ffff:10.0.0.1"}`), "as IPv4"},
		{"a zone", host(`{"address": "fd00::1%eth0"}`), "zone"},
		{"the session's DNS", host(`{"address": "10.0.0.1:53"}`), "port 53"},
		{"frisket's service address", host(`{"address": "192.0.2.2"}`), "frisket's own"},
		{"frisket's dummy address", host(`{"address": "[2001:db8::1]:22"}`), "frisket's own"},
		{"no user", host(`{"user": ""}`), "apps.ssh.hosts.server.user"},
		{"a user that is an option", host(`{"user": "-oProxyCommand=x"}`), "apps.ssh.hosts.server.user"},
		{"no host keys", host(`{"hostKeys": []}`), "apps.ssh.hosts.server.hostKeys: none"},
		{"a host key that is not one", host(`{"hostKeys": ["ssh-ed25519 nope"]}`), "apps.ssh.hosts.server.hostKeys[0]: not a key"},
		{"a host key with its host", host(fmt.Sprintf(`{"hostKeys": [%q]}`, "server "+key)), "hostKeys[0]"},
		{"a host key with a marker", host(fmt.Sprintf(`{"hostKeys": [%q]}`, "@cert-authority * "+key)), "hostKeys[0]"},
		{"a host key on two lines", host(fmt.Sprintf(`{"hostKeys": [%q]}`, key+"\n"+other)), "one key, on one line"},
		{"a host key twice", host(fmt.Sprintf(`{"hostKeys": [%q, %q]}`, key, key+" again")), "hostKeys[1] is listed twice"},
		{"an unmatched that is none", host(`{"unmatched": "maybe"}`), "apps.ssh.hosts.server.unmatched"},
		{"a word, which is an id until the catalogue says it is none", host(`{"allow": ["ls"]}`), ""},
		{"an id that is not one", host(`{"allow": ["List_Files"]}`), `apps.ssh.hosts.server.allow: "List_Files" is not an operation's id`},
		{"a category that is not one", host(`{"ask": ["category:"]}`), "apps.ssh.hosts.server.ask"},
		{"a pattern frisket would refuse", host(`{"refuse": ["rm  **"]}`), "apps.ssh.hosts.server.refuse: pattern"},
		{"a pattern with a quote", host(`{"allow": ["echo 'x' **"]}`), "or plain"},
		{"an assignment", host(`{"allow": ["PATH=/tmp **"]}`), "assignment"},
		{"a reserved word", host(`{"allow": ["time **"]}`), "reserved"},
		{"a word beginning =, zsh's command path", host(`{"allow": ["cat =deploy"]}`), "begins ="},
		{"a name in one list twice", host(`{"allow": ["remove", "remove"]}`), `allow: "remove" is listed twice`},
		{"a name in two lists", host(`{"allow": ["remove"], "refuse": ["remove"]}`), `refuse: "remove" is in allow too`},
		{"a pattern in two lists", host(`{"ask": ["ls **"], "refuse": ["ls **"]}`), `"ls **" is in ask too`},
		{"two machines at one address", fmt.Sprintf(`{"hosts": {"a": {"address": "10.0.0.1", "user": "u", "hostKeys": [%q]}, "b": {"address": "10.0.0.1:22", "user": "u", "hostKeys": [%q]}}}`, key, other), "apps.ssh.hosts.b.address: 10.0.0.1:22 is a's too"},
	} {
		var b Binding
		if err := json.Unmarshal([]byte(tc.binding), &b); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		err := b.Check("apps.ssh")
		if tc.said == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.said) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}

	var b Binding
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"hosts": {
		"server": {"address": "192.168.1.10", "user": "ops", "hostKeys": [%q], "allow": ["service-restart", "category:packages", "docker compose ps **"], "ask": ["*"], "refuse": ["**"], "unmatched": "refuse"},
		"gateway.lan": {"address": "[fd00::1]:2222", "user": "root", "hostKeys": [%q]}}}`, key, other)), &b); err != nil {
		t.Fatal(err)
	}
	if err := b.Check("apps.ssh"); err != nil {
		t.Errorf("what a grant may say was refused: %v", err)
	}
}

// merge is the JSON object base, its %q the key,
// and extra's members over it.
func merge(t *testing.T, base, key, extra string) string {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal([]byte(fmt.Sprintf(base, key)), &m); err != nil {
		t.Fatal(err)
	}
	if extra != "" {
		if err := json.Unmarshal([]byte(extra), &m); err != nil {
			t.Fatal(err)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
