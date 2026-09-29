// Package gcloudtest is Google's token endpoint for checks: it verifies each
// JWT-bearer grant against a service account's public key, as Google would,
// and answers with the status a check scripts, logging every request.
package gcloudtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// Request is one request the fake answered.
type Request struct {
	Code int
	// Wrong is what the fake found wrong with the grant, or "": "path",
	// "grant_type", "header", "signature", "claims", "iss", "aud", "scope",
	// "times".
	Wrong string
	// Token is the access token it granted, if it did.
	Token string
	// Assertion is the JWT it was sent.
	Assertion string
	At        time.Time
}

// Google is the fake. Its URL + "/token" is its token endpoint.
type Google struct {
	*httptest.Server
	public *rsa.PublicKey
	email  string

	mu     sync.Mutex
	codes  []int
	log    []Request
	served int
}

// New starts a fake that grants tokens to email, for grants public verifies.
func New(public *rsa.PublicKey, email string) *Google {
	g := &Google{public: public, email: email}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	return g
}

// TokenURL is the fake's token endpoint.
func (g *Google) TokenURL() string { return g.URL + "/token" }

// Answer queues statuses: each request takes the first, until none are
// left, when it is 200 if the grant verifies and 400 if not.
func (g *Google) Answer(codes ...int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.codes = append(g.codes, codes...)
}

// Log is every request so far.
func (g *Google) Log() []Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Request(nil), g.log...)
}

// Requests is how many requests the fake has answered.
func (g *Google) Requests() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.log)
}

func (g *Google) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	g.mu.Lock()
	code := http.StatusOK
	if len(g.codes) > 0 {
		code, g.codes = g.codes[0], g.codes[1:]
	}
	g.mu.Unlock()
	wrong := ""
	if r.URL.Path != "/token" {
		code, wrong = http.StatusNotFound, "path"
	} else if code == http.StatusOK {
		if wrong = g.verify(r.PostForm); wrong != "" {
			code = http.StatusBadRequest
		}
	}
	g.mu.Lock()
	g.served++
	n := g.served
	g.mu.Unlock()
	nonce := make([]byte, 8)
	rand.Read(nonce)
	var body map[string]any
	token := ""
	if code == http.StatusOK {
		token = fmt.Sprintf("ya29.fake-%d-%s", n, hex.EncodeToString(nonce))
		body = map[string]any{"access_token": token, "expires_in": 3599, "token_type": "Bearer"}
	} else {
		why := wrong
		if why == "" {
			why = fmt.Sprint(code)
		}
		body = map[string]any{"error": "invalid_grant", "error_description": "fake says no (" + why + ")"}
	}
	g.mu.Lock()
	g.log = append(g.log, Request{Code: code, Wrong: wrong, Token: token, Assertion: r.PostForm.Get("assertion"), At: time.Now()})
	g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}

func (g *Google) verify(form map[string][]string) string {
	if !reflect.DeepEqual(form["grant_type"], []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"}) {
		return "grant_type"
	}
	a := form["assertion"]
	if len(a) != 1 {
		return "header"
	}
	parts := strings.Split(a[0], ".")
	if len(parts) != 3 {
		return "header"
	}
	var header map[string]any
	if h, err := b64d(parts[0]); err != nil || json.Unmarshal(h, &header) != nil ||
		!reflect.DeepEqual(header, map[string]any{"alg": "RS256", "typ": "JWT"}) {
		return "header"
	}
	sig, err := b64d(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(g.public, crypto.SHA256, sum[:], sig) != nil {
		return "signature"
	}
	var claims map[string]any
	c, err := b64d(parts[1])
	if err != nil || json.Unmarshal(c, &claims) != nil {
		return "claims"
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"aud", "exp", "iat", "iss", "scope"}) {
		return "claims"
	}
	if claims["iss"] != g.email {
		return "iss"
	}
	if claims["aud"] != "https://oauth2.googleapis.com/token" {
		return "aud"
	}
	if claims["scope"] != "https://www.googleapis.com/auth/cloud-platform" {
		return "scope"
	}
	now := float64(time.Now().Unix())
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if !(now-60 <= iat && iat <= now+5) || !(0 < exp-iat && exp-iat <= 3600) {
		return "times"
	}
	return ""
}

func b64d(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Key is a service-account key file, as Google issues one, holding key in
// PKCS#8 PEM as openssl genpkey writes it.
func Key(key *rsa.PrivateKey, email, project string) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	b, _ := json.Marshal(map[string]any{
		"type":           "service_account",
		"project_id":     project,
		"private_key_id": "x",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   email,
		"client_id":      "1",
	})
	return b
}
