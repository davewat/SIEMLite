// Package entratest is a fake Microsoft Entra ID and Microsoft Graph, for
// testing SIEMLite's sign-in with Microsoft without a real directory.
package entratest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	Tenant       = "11111111-2222-3333-4444-555555555555"
	ClientID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	ClientSecret = "the-client-secret"
	AccessGroup  = "99999999-0000-0000-0000-000000000001"
	AdminGroup   = "99999999-0000-0000-0000-000000000002"
)

// Microsoft stands in for Microsoft Entra and Graph: signing keys, the token endpoint and Graph.
type Microsoft struct {
	// URL is the address to use as both the Authority and (plus /v1.0) Graph.
	URL string

	// Set between requests, not during them.
	GraphStatus  int    // answer Graph with this status when non-zero
	PageSize     int    // members per page (0: all in one)
	NextLinkHost string // when set, nextLink points here instead of back at the fake
	Opts         TokenOptions
	// BeforeCodeExchange, if set, runs as the sign-in code is being exchanged,
	// for tests of something changing in the middle of a sign-in.
	BeforeCodeExchange func()

	t       *testing.T
	srv     *httptest.Server
	key     *rsa.PrivateKey
	mu      sync.Mutex
	groups  map[string]map[string]bool // group -> object id -> account enabled
	pending struct{ nonce, challenge, redirect string }
	user    struct{ oid, upn string }
}

// TokenOptions make the next ID tokens wrong in one way, for tests of what
// SIEMLite refuses.
type TokenOptions struct {
	Aud, Tid, Iss string
	Expired       bool
	HS256         bool
	OtherKey      *rsa.PrivateKey
	NoNonce       bool
}

// Expect records the sign-in the next code belongs to, taken from the address
// SIEMLite sent the browser to, and who the person is.
func (f *Microsoft) Expect(authorizeURL, oid, upn string) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := u.Query()
	f.mu.Lock()
	f.pending.nonce, f.pending.challenge, f.pending.redirect = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")
	f.user.oid, f.user.upn = oid, upn
	f.mu.Unlock()
}

// Code is the authorization code the fake accepts.
const Code = "good-code"

// RSAKey makes a throwaway key, for signing tokens the fake's keys don't match.
func RSAKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// New starts a fake Microsoft that is stopped when the test ends.
func New(t *testing.T) *Microsoft {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &Microsoft{t: t, key: key, groups: map[string]map[string]bool{AccessGroup: {}, AdminGroup: {}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+Tenant+"/discovery/v2.0/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1",
			"n": b64u(key.N.Bytes()), "e": b64u(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/"+Tenant+"/oauth2/v2.0/token", f.token)
	mux.HandleFunc("/v1.0/", f.graph)
	f.srv = httptest.NewServer(mux)
	f.URL = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

func (f *Microsoft) fail(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func (f *Microsoft) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.Form.Get("grant_type") == "authorization_code" && f.BeforeCodeExchange != nil {
		f.BeforeCodeExchange()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Form.Get("client_id") != ClientID || r.Form.Get("client_secret") != ClientSecret {
		f.fail(w, 401, "invalid_client", "AADSTS7000215: Invalid client secret provided. Trace ID: abc")
		return
	}
	switch r.Form.Get("grant_type") {
	case "client_credentials":
		json.NewEncoder(w).Encode(map[string]any{"access_token": "graph-token", "expires_in": 3600})
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "good-code" || b64u(sum[:]) != f.pending.challenge || r.Form.Get("redirect_uri") != f.pending.redirect {
			f.fail(w, 400, "invalid_grant", "AADSTS70008: The provided authorization code is invalid.")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id_token": f.idToken(), "access_token": "user-token"})
	default:
		f.fail(w, 400, "unsupported_grant_type", "no")
	}
}

// idToken builds an ID token for the user the next code belongs to.
func (f *Microsoft) idToken() string {
	o := f.Opts
	aud, tid, iss := or(o.Aud, ClientID), or(o.Tid, Tenant), or(o.Iss, f.srv.URL+"/"+Tenant+"/v2.0")
	exp := time.Now().Add(time.Hour)
	if o.Expired {
		exp = time.Now().Add(-time.Hour)
	}
	cl := map[string]any{"iss": iss, "aud": aud, "tid": tid, "oid": f.user.oid, "preferred_username": f.user.upn,
		"name": "Test Person", "exp": exp.Unix(), "nbf": time.Now().Add(-time.Minute).Unix(), "iat": time.Now().Unix()}
	if !o.NoNonce {
		cl["nonce"] = f.pending.nonce
	}
	alg := "RS256"
	if o.HS256 {
		alg = "HS256"
	}
	hb, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": "k1"})
	pb, _ := json.Marshal(cl)
	in := b64u(hb) + "." + b64u(pb)
	sign := f.key
	if o.OtherKey != nil {
		sign = o.OtherKey
	}
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, sign, crypto.SHA256, sum[:])
	return in + "." + b64u(sig)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (f *Microsoft) graph(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer graph-token" {
		w.WriteHeader(401)
		return
	}
	if f.GraphStatus != 0 {
		w.WriteHeader(f.GraphStatus)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1.0/groups/")
	gid, tail, _ := strings.Cut(rest, "/")
	members, ok := f.groups[gid]
	if !ok {
		w.WriteHeader(404)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "Request_ResourceNotFound", "message": "no such group"}})
		return
	}
	switch {
	case tail == "" && r.Method == "GET":
		json.NewEncoder(w).Encode(map[string]string{"id": gid, "displayName": "Group " + gid[len(gid)-1:]})
	case tail == "checkMemberObjects" && r.Method == "POST":
		var in struct{ IDs []string }
		json.NewDecoder(r.Body).Decode(&in)
		out := []string{}
		for _, id := range in.IDs {
			if members[strings.ToLower(id)] {
				out = append(out, id)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"value": out})
	case tail == "transitiveMembers/microsoft.graph.user" && r.Method == "GET":
		var ids []string
		for id := range members {
			ids = append(ids, id)
		}
		sortStrings(ids)
		size := f.PageSize
		if size == 0 {
			size = 1000
		}
		skip := 0
		fmt.Sscanf(r.URL.Query().Get("skip"), "%d", &skip)
		end := min(skip+size, len(ids))
		page := []map[string]any{}
		for _, id := range ids[skip:end] {
			page = append(page, map[string]any{"id": id, "accountEnabled": members[id]})
		}
		res := map[string]any{"value": page}
		if end < len(ids) {
			host := f.srv.URL
			if f.NextLinkHost != "" {
				host = f.NextLinkHost
			}
			res["@odata.nextLink"] = host + "/v1.0/groups/" + gid + "/transitiveMembers/microsoft.graph.user?skip=" + fmt.Sprint(end)
		}
		json.NewEncoder(w).Encode(res)
	default:
		w.WriteHeader(404)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Set puts a person in a group (enabled says whether their Microsoft account is).
func (f *Microsoft) Set(group, oid string, enabled bool) {
	f.mu.Lock()
	f.groups[group][strings.ToLower(oid)] = enabled
	f.mu.Unlock()
}

// Remove takes a person out of a group.
func (f *Microsoft) Remove(group, oid string) {
	f.mu.Lock()
	delete(f.groups[group], strings.ToLower(oid))
	f.mu.Unlock()
}
