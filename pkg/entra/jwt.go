package entra

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// claims are the parts of an ID token SIEMLite reads.
type claims struct {
	Issuer    string  `json:"iss"`
	Audience  string  `json:"aud"`
	Expires   float64 `json:"exp"`
	NotBefore float64 `json:"nbf"`
	Nonce     string  `json:"nonce"`
	TenantID  string  `json:"tid"`
	ObjectID  string  `json:"oid"`
	Username  string  `json:"preferred_username"`
	Name      string  `json:"name"`
	Email     string  `json:"email"`
}

const clockSkew = 2 * time.Minute

// keySet holds a tenant's signing keys, fetched from Microsoft.
type keySet struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// key returns the signing key with the given id, refreshing the set once if
// it isn't known (Microsoft rotates keys).
func (k *keySet) key(ctx context.Context, hc *http.Client, url, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if pub, ok := k.keys[kid]; ok {
		return pub, nil
	}
	if time.Since(k.fetched) < 30*time.Second && k.keys != nil {
		return nil, errors.New("unknown signing key")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch signing keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch signing keys: %s", resp.Status)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(limit(resp)).Decode(&set); err != nil {
		return nil, fmt.Errorf("read signing keys: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jk := range set.Keys {
		if jk.Kty != "RSA" {
			continue
		}
		n, err1 := b64(jk.N)
		e, err2 := b64(jk.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			continue
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		keys[jk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	k.keys, k.fetched = keys, time.Now()
	if pub, ok := keys[kid]; ok {
		return pub, nil
	}
	return nil, errors.New("unknown signing key")
}

// verifyIDToken checks an ID token's signature and claims: signed by the
// tenant's key with RS256, from this tenant and issuer, for this app, current,
// and carrying the nonce this sign-in started with.
func (s *Service) verifyIDToken(ctx context.Context, raw string, cfg Config, nonce string, now time.Time) (*claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("the ID token is malformed")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return nil, errors.New("the ID token is malformed")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, errors.New("the ID token is malformed")
	}
	// Only RS256: never "none", and never a symmetric algorithm keyed by a public value.
	if header.Alg != "RS256" || header.Kid == "" {
		return nil, errors.New("the ID token isn't signed with RS256")
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, errors.New("the ID token is malformed")
	}
	pub, err := s.keys(cfg.TenantID).key(ctx, s.http, s.authority()+"/"+cfg.TenantID+"/discovery/v2.0/keys", header.Kid)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("the ID token's signature is invalid")
	}
	pb, err := b64(parts[1])
	if err != nil {
		return nil, errors.New("the ID token is malformed")
	}
	var c claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, errors.New("the ID token is malformed")
	}
	switch {
	case c.Issuer != s.authority()+"/"+cfg.TenantID+"/v2.0":
		return nil, errors.New("the ID token is from a different issuer")
	case c.TenantID != cfg.TenantID:
		return nil, errors.New("the ID token is from a different tenant")
	case c.Audience != cfg.ClientID:
		return nil, errors.New("the ID token is for a different app")
	case c.Expires == 0 || now.After(time.Unix(int64(c.Expires), 0).Add(clockSkew)):
		return nil, errors.New("the ID token has expired")
	case c.NotBefore != 0 && now.Before(time.Unix(int64(c.NotBefore), 0).Add(-clockSkew)):
		return nil, errors.New("the ID token isn't valid yet")
	case nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1:
		return nil, errors.New("the ID token doesn't belong to this sign-in")
	case !isGUID(c.ObjectID):
		return nil, errors.New("the ID token has no user object ID")
	}
	c.ObjectID = strings.ToLower(c.ObjectID)
	return &c, nil
}
