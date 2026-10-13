// Package signertest stands in for quoin-signer in tests: an SSH agent on
// a socket of its own whose policy-sign@quoin extension answers as the
// signer does once a person has allowed it -- or refused -- with a key of
// its own, which the allowed signers file it writes allows in every
// quoin-policy namespace. It reads and answers with quoin's own policysign,
// the wire the real signer serves, so the stand-in cannot drift from it.
// What it is asked is kept.
package signertest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/danielbodart/quoin/policysign"
	"github.com/danielbodart/quoin/projpolicy"
)

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
	asked  []policysign.Request
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
	line := `dan namespaces="` + projpolicy.NamespacePrefix + `:*" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))) + "\n"
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
func (s *Signer) Asked() []policysign.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]policysign.Request(nil), s.asked...)
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
	if typ != policysign.Extension {
		return nil, agent.ErrExtensionUnsupported
	}
	refused := func(why string) ([]byte, error) {
		return policysign.Reply(policysign.Response{Error: why}), nil
	}
	r, err := policysign.DecodeRequest(contents)
	if err != nil {
		return refused(err.Error())
	}
	e.s.mu.Lock()
	e.s.asked = append(e.s.asked, r)
	refuse := e.s.refuse
	e.s.mu.Unlock()
	if refuse {
		return refused("refused")
	}
	if !projpolicy.Canonical(r.New) {
		return refused("the new file is not canonical: run quoin policy fmt on it first")
	}
	ns, err := projpolicy.Namespace(r.Root, e.s.Home)
	if err != nil {
		return refused(err.Error())
	}
	sig, err := projpolicy.Sign(rand.Reader, e.s.key, ns, r.New)
	if err != nil {
		return nil, errors.New("sign failed")
	}
	return policysign.Reply(policysign.Response{Sig: sig}), nil
}
