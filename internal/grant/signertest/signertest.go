// Package signertest stands in for frisket-signer in tests: an SSH agent
// on a socket of its own whose policy-sign@frisket extension answers as
// the signer does once a person has allowed it -- or refused -- with a key
// of its own, which the allowed signers file it writes allows in every
// frisket-policy namespace. What it is asked is kept.
package signertest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/danielbodart/frisket/projpolicy"
)

// Request is policy-sign's, as frisket's signer reads it.
type Request struct {
	Root   string `json:"root"`
	Name   string `json:"name"`
	New    []byte `json:"new"`
	Old    []byte `json:"old,omitempty"`
	OldSig []byte `json:"oldSig,omitempty"`
}

// Signer is the stand-in. Socket is its agent's, AllowedSigners the file
// allowing its key, Home the home a root's namespace is named from.
type Signer struct {
	Socket         string
	AllowedSigners string
	Home           string

	key ssh.Signer
	ln  net.Listener

	mu     sync.Mutex
	refuse bool
	asked  []Request
}

// New is a signer for a user whose home is home, serving until the test
// ends.
func New(t *testing.T, home string) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// A socket's path is at most 108 bytes, which a test's own directory
	// may not be.
	dir, err := os.MkdirTemp("", "signer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := &Signer{
		Socket:         filepath.Join(dir, "agent"),
		AllowedSigners: filepath.Join(dir, "allowed_signers"),
		Home:           home,
		key:            key,
	}
	line := `dan namespaces="frisket-policy:*" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))) + "\n"
	if err := os.WriteFile(s.AllowedSigners, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				agent.ServeAgent(extension{agent.NewKeyring().(agent.ExtendedAgent), s}, c)
			}()
		}
	}()
	return s
}

// Refuse makes the person refuse every signing from now, or allow it.
func (s *Signer) Refuse(refuse bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = refuse
}

// Asked is every policy-sign the signer was asked, in order.
func (s *Signer) Asked() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.asked...)
}

// Sign is the signature of b, root's policy file, in root's namespace, as
// a person would have the signer make it, without being asked.
func (s *Signer) Sign(t *testing.T, root string, b []byte) []byte {
	t.Helper()
	ns, err := projpolicy.Namespace(root, s.Home)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := projpolicy.Sign(rand.Reader, s.key, ns, b)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

type extension struct {
	agent.ExtendedAgent
	s *Signer
}

func (e extension) Extension(typ string, contents []byte) ([]byte, error) {
	if typ != "policy-sign@frisket" {
		return nil, agent.ErrExtensionUnsupported
	}
	reply := func(v any) ([]byte, error) {
		b, err := json.Marshal(v)
		return append([]byte{6}, b...), err
	}
	var r Request
	if err := json.Unmarshal(contents, &r); err != nil {
		return reply(map[string]string{"error": "request: " + err.Error()})
	}
	e.s.mu.Lock()
	e.s.asked = append(e.s.asked, r)
	refuse := e.s.refuse
	e.s.mu.Unlock()
	if refuse {
		return reply(map[string]string{"error": "refused"})
	}
	if !projpolicy.Canonical(r.New) {
		return reply(map[string]string{"error": "the new file is not canonical: run frisket policy fmt on it first"})
	}
	ns, err := projpolicy.Namespace(r.Root, e.s.Home)
	if err != nil {
		return reply(map[string]string{"error": err.Error()})
	}
	sig, err := projpolicy.Sign(rand.Reader, e.s.key, ns, r.New)
	if err != nil {
		return nil, errors.New("sign failed")
	}
	return reply(map[string]any{"sig": sig})
}
