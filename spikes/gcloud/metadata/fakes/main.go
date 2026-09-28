package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	logMu   sync.Mutex
	logFile *os.File
	start   = time.Now()
)

func logj(m map[string]any) {
	m["t"] = fmt.Sprintf("%.3f", time.Since(start).Seconds())
	b, _ := json.Marshal(m)
	logMu.Lock()
	logFile.Write(append(b, '\n'))
	logMu.Unlock()
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

const (
	project = "frisket-spike"
	projNum = "123456789012"
	email   = "spike@frisket-spike.iam.gserviceaccount.com"
)

var scopes = []string{"https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email"}

func fakeJWT(aud string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"proxy-injected","typ":"JWT"}`))
	now := time.Now().Unix()
	p, _ := json.Marshal(map[string]any{"aud": aud, "azp": "1", "email": email, "email_verified": true, "exp": now + 3600, "iat": now, "iss": "https://accounts.google.com", "sub": "1"})
	return h + "." + base64.RawURLEncoding.EncodeToString(p) + ".proxy-injected"
}

func metadataHandler(tag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logj(map[string]any{"srv": tag, "method": r.Method, "host": r.Host, "path": r.URL.Path, "query": r.URL.RawQuery, "headers": r.Header, "remote": r.RemoteAddr})
		if tag != "metadata" {
			http.Error(w, "trap", 599)
			return
		}
		if os.Getenv("NO_FLAVOR") == "" {
			w.Header().Set("Metadata-Flavor", "Google")
		}
		w.Header().Set("Server", "Metadata Server for VM")
		p := r.URL.Path
		q := r.URL.Query()
		recursive := q.Get("recursive") == "true"
		text := func(s string) { w.Header().Set("Content-Type", "application/text"); io.WriteString(w, s) }
		js := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
		// Real GCE requires Metadata-Flavor on /computeMetadata/v1 paths
		if strings.HasPrefix(p, "/computeMetadata/") && r.Header.Get("Metadata-Flavor") != "Google" && os.Getenv("NO_REQUIRE_FLAVOR") == "" {
			w.WriteHeader(403)
			text("Missing required header \"Metadata-Flavor\": \"Google\"\n")
			return
		}
		for _, d := range strings.Split(os.Getenv("MD_DENY"), ",") {
			if d != "" && regexp.MustCompile(d).MatchString(r.URL.RequestURI()) {
				logj(map[string]any{"srv": tag, "DENIED": r.URL.RequestURI()})
				w.WriteHeader(404)
				text("denied\n")
				return
			}
		}
		sa := map[string]any{"aliases": []string{"default"}, "email": email, "scopes": scopes}
		base := "/computeMetadata/v1/"
		rel := strings.TrimPrefix(p, base)
		if !strings.HasPrefix(p, base) && p != "/" && p != "/computeMetadata/v1" && p != "/computeMetadata/" {
			w.WriteHeader(404)
			return
		}
		switch {
		case p == "/":
			text("0.1/\ncomputeMetadata/\n")
		case p == "/computeMetadata/":
			text("v1/\n")
		case p == "/computeMetadata/v1" || p == base:
			text("instance/\noauth2/\nproject/\nuniverse/\n")
		case rel == "instance" || rel == "instance/":
			text("hostname\nid\nservice-accounts/\nzone\n")
		case rel == "instance/service-accounts" || rel == "instance/service-accounts/":
			if recursive {
				js(map[string]any{"default": sa, email: sa})
			} else {
				text("default/\n" + email + "/\n")
			}
		case rel == "instance/service-accounts/default" || rel == "instance/service-accounts/default/" ||
			rel == "instance/service-accounts/"+email || rel == "instance/service-accounts/"+email+"/":
			if recursive {
				js(sa)
			} else {
				text("aliases\nemail\nidentity\nscopes\ntoken\n")
			}
		case strings.HasSuffix(rel, "/email") && strings.HasPrefix(rel, "instance/service-accounts/"):
			text(email)
		case strings.HasSuffix(rel, "/aliases"):
			text("default\n")
		case strings.HasSuffix(rel, "/scopes") && strings.HasPrefix(rel, "instance/service-accounts/"):
			text(strings.Join(scopes, "\n") + "\n")
		case strings.HasSuffix(rel, "/token") && strings.HasPrefix(rel, "instance/service-accounts/"):
			ttl := 3599
			fmt.Sscan(env("TOKEN_TTL", "3599"), &ttl)
			js(map[string]any{"access_token": "proxy-injected", "expires_in": ttl, "token_type": "Bearer"})
		case strings.HasSuffix(rel, "/identity") && strings.HasPrefix(rel, "instance/service-accounts/"):
			if os.Getenv("IDTOKEN_MODE") == "jwt" {
				text(fakeJWT(q.Get("audience")))
			} else {
				text("proxy-injected")
			}
		case rel == "project/project-id":
			text(project)
		case rel == "project/numeric-project-id":
			text(projNum)
		case rel == "universe/universe-domain" || rel == "universe/universe_domain":
			text("googleapis.com")
		case rel == "instance/zone":
			text("projects/" + projNum + "/zones/europe-west2-a")
		case rel == "instance/id":
			text("4242424242424242424")
		case rel == "instance/hostname":
			text("spike.europe-west2-a.c.frisket-spike.internal")
		default:
			logj(map[string]any{"srv": tag, "UNKNOWN": p, "query": r.URL.RawQuery})
			w.WriteHeader(404)
			text("not found\n")
		}
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	logj(map[string]any{"srv": "api", "proto": r.Proto, "method": r.Method, "host": r.Host, "path": r.URL.Path, "query": r.URL.RawQuery, "authorization": r.Header.Get("Authorization"), "headers": r.Header, "bodylen": len(body)})
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	p := r.URL.Path
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(200)
		w.Write([]byte{0, 0, 0, 0, 0})
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "")
		return
	}
	switch {
	case host == "storage.googleapis.com" && (p == "/storage/v1/b" || p == "/storage/v1/b/"):
		io.WriteString(w, `{"kind":"storage#buckets","items":[{"kind":"storage#bucket","id":"spike-bucket","name":"spike-bucket","projectNumber":"123456789012","location":"EUROPE-WEST2","storageClass":"STANDARD","timeCreated":"2026-01-01T00:00:00.000Z","updated":"2026-01-01T00:00:00.000Z","etag":"CAE="}]}`)
	case host == "storage.googleapis.com" && strings.HasSuffix(p, "/o"):
		io.WriteString(w, `{"kind":"storage#objects","items":[{"kind":"storage#object","name":"hello.txt","bucket":"spike-bucket","size":"5","generation":"1","metageneration":"1","contentType":"text/plain","timeCreated":"2026-01-01T00:00:00.000Z","updated":"2026-01-01T00:00:00.000Z","storageClass":"STANDARD"}]}`)
	case host == "storage.googleapis.com" && strings.HasPrefix(p, "/storage/v1/b/") && strings.Count(p, "/") == 4:
		io.WriteString(w, `{"kind":"storage#bucket","id":"spike-bucket","name":"spike-bucket","projectNumber":"123456789012","location":"EUROPE-WEST2","storageClass":"STANDARD","timeCreated":"2026-01-01T00:00:00.000Z","updated":"2026-01-01T00:00:00.000Z","etag":"CAE=","metageneration":"1"}`)
	case host == "cloudresourcemanager.googleapis.com" && strings.HasPrefix(p, "/v1/projects/"):
		io.WriteString(w, `{"projectNumber":"123456789012","projectId":"frisket-spike","lifecycleState":"ACTIVE","name":"frisket-spike","createTime":"2026-01-01T00:00:00.000Z","parent":{"type":"organization","id":"1"}}`)
	case host == "cloudresourcemanager.googleapis.com" && strings.HasPrefix(p, "/v3/projects/"):
		io.WriteString(w, `{"name":"projects/123456789012","parent":"organizations/1","projectId":"frisket-spike","state":"ACTIVE","displayName":"frisket-spike","createTime":"2026-01-01T00:00:00.000Z","etag":"W/\"x\""}`)
	case host == "pubsub.googleapis.com" && strings.HasSuffix(p, "/topics"):
		io.WriteString(w, `{}`)
	default:
		logj(map[string]any{"srv": "api", "UNKNOWN": host + p})
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":404,"message":"fake: unknown","status":"NOT_FOUND"}}`)
	}
}

func dnsServer(addr, apiIP, trapIP string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
		var ans net.IP
		denied := false
		for _, d := range strings.Split(os.Getenv("DNS_DENY"), ",") {
			if d != "" && name == d {
				denied = true
			}
		}
		if q.Type == dnsmessage.TypeA && !denied {
			if strings.HasSuffix(name, ".googleapis.com") || name == "googleapis.com" {
				ans = net.ParseIP(apiIP).To4()
			} else if name == "metadata.google.internal" || name == "metadata" {
				ans = net.ParseIP(trapIP).To4()
			}
		}
		logj(map[string]any{"srv": "dns", "name": name, "type": q.Type.String(), "answer": fmt.Sprint(ans)})
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true, RecursionDesired: h.RecursionDesired, RCode: func() dnsmessage.RCode {
			if denied || ans == nil && !(strings.HasSuffix(name, "googleapis.com") || name == "metadata.google.internal") {
				return dnsmessage.RCodeNameError
			}
			return dnsmessage.RCodeSuccess
		}()})
		b.StartQuestions()
		b.Question(q)
		b.StartAnswers()
		if ans != nil {
			var a [4]byte
			copy(a[:], ans)
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: a})
		}
		out, _ := b.Finish()
		pc.WriteTo(out, from)
	}
}

func main() {
	var err error
	logFile, err = os.OpenFile(env("LOG", "fakes.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	mdAddr := env("MD_ADDR", "192.0.2.2:80")
	apiAddr := env("API_ADDR", "192.0.2.10:443")
	trapAddr := env("TRAP_ADDR", "169.254.169.254:80")
	go func() { log.Fatal(http.ListenAndServe(mdAddr, metadataHandler("metadata"))) }()
	go func() { log.Fatal(http.ListenAndServe(trapAddr, metadataHandler("TRAP-169.254.169.254"))) }()
	go func() {
		ln, err := net.Listen("tcp", "169.254.169.254:443")
		if err != nil {
			log.Fatal(err)
		}
		for {
			c, err := ln.Accept()
			if err == nil {
				logj(map[string]any{"srv": "TRAP-169.254.169.254:443", "remote": c.RemoteAddr().String()})
				c.Close()
			}
		}
	}()
	go dnsServer(env("DNS_ADDR", "127.0.0.53:53"), "192.0.2.10", "169.254.169.254")
	cert, err := tls.LoadX509KeyPair(env("CERT", "../pki/api.crt"), env("KEY", "../pki/api.key"))
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: apiAddr, Handler: http.HandlerFunc(apiHandler), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
