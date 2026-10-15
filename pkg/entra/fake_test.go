package entra

import (
	"context"
	"net/url"
	"path/filepath"
	"sync"
	"testing"

	"siemlite/pkg/entra/entratest"
	"siemlite/pkg/secret"
	"siemlite/pkg/storage"
)

const (
	tenant      = entratest.Tenant
	clientID    = entratest.ClientID
	clientPass  = entratest.ClientSecret
	accessGroup = entratest.AccessGroup
	adminGroup  = entratest.AdminGroup
)

// env is a Service wired to a real database and the fake Microsoft.
type env struct {
	t    *testing.T
	svc  *Service
	repo *storage.Repository
	ms   *entratest.Microsoft
	cfg  Config
	box  *secret.Box
	st   *memStore
}

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memStore) Setting(_ context.Context, k, def string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return v, nil
	}
	return def, nil
}

func (s *memStore) SetSetting(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := bg()
	db, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := storage.NewRepository(db)
	ms := entratest.New(t)
	box := secret.NewBox(filepath.Join(t.TempDir(), "k.key"))
	st := &memStore{m: map[string]string{}}
	svc := NewService(st, repo, box, nil)
	svc.Authority, svc.Graph = ms.URL, ms.URL+"/v1.0"
	cfg := Config{TenantID: tenant, ClientID: clientID, PublicURL: "https://siem.example.com:8443", AccessGroupID: accessGroup}
	e := &env{t: t, svc: svc, repo: repo, ms: ms, cfg: cfg, box: box, st: st}
	pw := clientPass
	if err := svc.Save(ctx, cfg, &pw); err != nil {
		t.Fatal(err)
	}
	return e
}

// signIn runs a whole sign-in as the person (oid, upn) and returns the result.
func (e *env) signIn(oid, upn string) (*storage.User, error) {
	e.t.Helper()
	authURL, cookie, err := e.svc.BeginLogin(bg())
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	e.ms.Expect(authURL, oid, upn)
	return e.svc.CompleteLogin(bg(), entratest.Code, q.Get("state"), cookie)
}

func code(err error) string {
	if le, ok := err.(*LoginError); ok {
		return le.Code
	}
	if err == nil {
		return ""
	}
	return "other:" + err.Error()
}

func bg() context.Context { return context.Background() }
