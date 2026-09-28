package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"
)

var b64 = base64.RawURLEncoding

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func pad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func main() {
	switch os.Args[1] {
	case "genkey":
		fs := flag.NewFlagSet("genkey", flag.ExitOnError)
		kt := fs.String("type", "rsa", "rsa|ec")
		out := fs.String("out", "", "pem")
		jwks := fs.String("jwks", "", "jwks out")
		kid := fs.String("kid", "k1", "")
		fs.Parse(os.Args[2:])
		var der []byte
		var jwk map[string]string
		if *kt == "rsa" {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			must(err)
			der, _ = x509.MarshalPKCS8PrivateKey(k)
			jwk = map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": *kid,
				"n": b64.EncodeToString(k.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
		} else {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			must(err)
			der, _ = x509.MarshalPKCS8PrivateKey(k)
			jwk = map[string]string{"kty": "EC", "alg": "ES256", "use": "sig", "kid": *kid, "crv": "P-256",
				"x": b64.EncodeToString(pad(k.X.Bytes(), 32)), "y": b64.EncodeToString(pad(k.Y.Bytes(), 32))}
		}
		must(os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600))
		j, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
		must(os.WriteFile(*jwks, j, 0644))
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		key := fs.String("key", "", "")
		kid := fs.String("kid", "k1", "")
		iss := fs.String("iss", "", "")
		sub := fs.String("sub", "", "")
		aud := fs.String("aud", "", "")
		iatOff := fs.Duration("iat", 0, "offset from now")
		ttl := fs.Duration("ttl", 5*time.Minute, "exp - iat")
		omit := fs.String("omit", "", "claim to omit")
		out := fs.String("out", "", "")
		fs.Parse(os.Args[2:])
		p, _ := os.ReadFile(*key)
		blk, _ := pem.Decode(p)
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		must(err)
		alg := "RS256"
		if _, ok := k.(*ecdsa.PrivateKey); ok {
			alg = "ES256"
		}
		now := time.Now().Add(*iatOff)
		claims := map[string]any{"iss": *iss, "sub": *sub, "aud": *aud, "iat": now.Unix(), "exp": now.Add(*ttl).Unix()}
		if *omit != "" {
			delete(claims, *omit)
		}
		h, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": *kid})
		c, _ := json.Marshal(claims)
		si := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
		d := sha256.Sum256([]byte(si))
		var sig []byte
		switch kk := k.(type) {
		case *rsa.PrivateKey:
			sig, err = rsa.SignPKCS1v15(rand.Reader, kk, crypto.SHA256, d[:])
			must(err)
		case *ecdsa.PrivateKey:
			r, s, err := ecdsa.Sign(rand.Reader, kk, d[:])
			must(err)
			sig = append(pad(r.Bytes(), 32), pad(s.Bytes(), 32)...)
		}
		must(os.WriteFile(*out, []byte(si+"."+b64.EncodeToString(sig)), 0600))
	}
}
