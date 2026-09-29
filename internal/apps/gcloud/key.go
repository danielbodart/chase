package gcloud

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danielbodart/chase/internal/files"
)

// The session's key (docs/gcloud.md, decision 2): a key file of the ordinary
// service_account shape, naming the project's service account and its
// project, whose private key chase made for the checkout and Google has never
// seen. Every Google client finds it through GOOGLE_APPLICATION_CREDENTIALS
// and signs with it; frisket holds its public half and answers what it signs
// with the placeholder. A leaked one is worth nothing outside frisket.

// sessionKeyFile is the key file's shape, in the order Google's own have it.
type sessionKeyFile struct {
	Type           string `json:"type"`
	ProjectID      string `json:"project_id"`
	PrivateKeyID   string `json:"private_key_id"`
	PrivateKey     string `json:"private_key"`
	ClientEmail    string `json:"client_email"`
	AuthURI        string `json:"auth_uri"`
	TokenURI       string `json:"token_uri"`
	UniverseDomain string `json:"universe_domain"`
}

// keyPath is the checkout's key for email in project: one per account and
// project, so a session launched with another leaves this one's alone.
func keyPath(envdir, email, project string) string {
	sum := sha256.Sum256([]byte(email + " " + project))
	return filepath.Join(envdir, "gcloud-key-"+hex.EncodeToString(sum[:])[:16]+".json")
}

// sessionKey is the checkout's key for email in project, made once and kept
// in envdir, and its public half as PEM. It is made under envdir's lock, so
// two launches of one checkout make one key between them.
func sessionKey(envdir, email, project string) (path, public string, err error) {
	if err := os.MkdirAll(envdir, 0o700); err != nil {
		return "", "", err
	}
	unlock, err := files.Lock(envdir)
	if err != nil {
		return "", "", err
	}
	defer unlock()
	path = keyPath(envdir, email, project)
	b, err := os.ReadFile(path)
	if err != nil || !names(b, email, project) {
		if b, err = newKey(email, project); err != nil {
			return "", "", err
		}
		if err := files.WriteAtomic(path, b, 0o600); err != nil {
			return "", "", err
		}
	}
	public, err = publicHalf(b)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", path, err)
	}
	return path, public, nil
}

// names is whether a key file is for email in project. What else it holds
// is not looked at: the key is the checkout's, and was made here.
func names(b []byte, email, project string) bool {
	var k map[string]any
	return json.Unmarshal(b, &k) == nil && k["client_email"] == email && k["project_id"] == project
}

// newKey is a new key file: an RSA-2048 key of its own, as openssl genpkey
// wrote it, and a random private_key_id.
func newKey(email, project string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 20)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err = enc.Encode(sessionKeyFile{
		Type:           "service_account",
		ProjectID:      project,
		PrivateKeyID:   hex.EncodeToString(id),
		PrivateKey:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		ClientEmail:    email,
		AuthURI:        "https://accounts.google.com/o/oauth2/auth",
		TokenURI:       "https://oauth2.googleapis.com/token",
		UniverseDomain: "googleapis.com",
	})
	return out.Bytes(), err
}

// publicHalf is the key file's public key, PEM, as `openssl pkey -pubout`
// gave it through a command substitution: with no newline at the end.
func publicHalf(b []byte) (string, error) {
	var k struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return "", errors.New("the key file is not JSON")
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return "", errors.New("the key file holds no private key")
	}
	var signer crypto.Signer
	if p, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, _ = p.(crypto.Signer)
	} else if p, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		signer = p
	} else if p, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		signer = p
	}
	if signer == nil {
		return "", errors.New("the key file's private key does not parse")
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "\n"), nil
}
