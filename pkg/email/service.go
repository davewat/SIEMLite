package email

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"siemlite/pkg/integrations"
)

const settingKey = "smtp"

// Store is where settings are kept (storage.Repository).
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// KeyPath is the encryption key's file, beside the database.
func KeyPath(dbPath string) string {
	return strings.TrimSuffix(dbPath, filepath.Ext(dbPath)) + "-secret.key"
}

// Service reads and saves the SMTP settings and sends mail with them.
type Service struct {
	store   Store
	keyPath string
	mu      sync.Mutex // one save at a time
}

// NewService returns a Service keeping its password key at keyPath.
func NewService(store Store, keyPath string) *Service {
	return &Service{store: store, keyPath: keyPath}
}

// stored is what is saved: the settings, and the password sealed.
type stored struct {
	Config
	Password string `json:"password,omitempty"`
	// Disabled turns email off while keeping its settings. It is a "not" so
	// that settings saved before the Integrations page existed stay on.
	Disabled bool `json:"disabled,omitempty"`
}

// View is what the System page shows. The password is never included.
type View struct {
	Config
	Configured  bool `json:"configured"`
	Enabled     bool `json:"enabled"`
	HasPassword bool `json:"has_password"`
	// PasswordUnreadable means a password was saved but this server's key
	// can't open it, as after a backup was restored onto another server.
	PasswordUnreadable bool `json:"password_unreadable,omitempty"`
}

func (s *Service) load(ctx context.Context) (stored, error) {
	raw, err := s.store.Setting(ctx, settingKey, "")
	if err != nil || raw == "" {
		return stored{}, err
	}
	var st stored
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return stored{}, fmt.Errorf("saved email settings are damaged: %w", err)
	}
	return st, nil
}

// Get returns the saved settings.
func (s *Service) Get(ctx context.Context) (View, error) {
	st, err := s.load(ctx)
	if err != nil {
		return View{}, err
	}
	v := View{Config: st.Config, Configured: st.Host != "", HasPassword: st.Password != ""}
	v.Enabled = v.Configured && !st.Disabled
	if st.Password != "" {
		if _, err := s.open(st.Password); err != nil {
			v.PasswordUnreadable = true
		}
	}
	if v.Config.Security == "" {
		v.Config.Security = SecuritySTARTTLS
	}
	if v.Config.Port == 0 {
		v.Config.Port = DefaultPort(v.Config.Security)
	}
	return v, nil
}

// Save stores cfg. A nil password keeps the saved one; a non-nil one replaces it
// (an empty string removes it). A config with no host clears everything.
func (s *Service) Save(ctx context.Context, cfg Config, password *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.FromAddress = strings.TrimSpace(cfg.FromAddress)
	cfg.FromName = strings.TrimSpace(cfg.FromName)
	if cfg.Host == "" {
		return s.store.SetSetting(ctx, settingKey, "")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	old, err := s.load(ctx)
	if err != nil {
		old = stored{} // damaged settings are replaced
	}
	// A saved password stays with the server it was saved for. Pointing the
	// settings at a different server (or login) needs the password typed again.
	if password == nil && old.Password != "" && !old.Config.sameServer(cfg) {
		return InputError("You changed the server or login, so enter the password again. The saved password is only used with the server it was saved for.")
	}
	st := stored{Config: cfg, Password: old.Password, Disabled: old.Disabled}
	if password != nil {
		st.Password = ""
		if *password != "" {
			if st.Password, err = s.seal(*password); err != nil {
				return err
			}
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, settingKey, string(b))
}

// Configured reports whether a server is set up and email is on.
func (s *Service) Configured(ctx context.Context) bool {
	v, err := s.Get(ctx)
	return err == nil && v.Enabled
}

// The Integrations page's view of email.

// ID is the integration's id.
func (s *Service) ID() string { return "email" }

// Name is what the page calls it.
func (s *Service) Name() string { return "Email" }

// Description says what it is for.
func (s *Service) Description() string {
	return "Send email through your own mail server, for the features that notify people."
}

// Info reports the card's state.
func (s *Service) Info(ctx context.Context) (integrations.Info, error) {
	v, err := s.Get(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	info := integrations.Info{Configured: v.Configured, Enabled: v.Enabled}
	if v.Configured {
		info.Summary = fmt.Sprintf("Sending as %s through %s:%d.", v.FromAddress, v.Host, v.Port)
		if v.PasswordUnreadable {
			info.Summary += " The saved password can't be read on this server; enter it again."
		}
	}
	return info, nil
}

// SetEnabled turns email on or off without touching the settings.
func (s *Service) SetEnabled(ctx context.Context, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	if st.Host == "" {
		return InputError("Set up the mail server first.")
	}
	st.Disabled = !on
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, settingKey, string(b))
}

// Send mails m through the saved server.
func (s *Service) Send(ctx context.Context, m Message) error {
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	if st.Host == "" {
		return errors.New("Email isn't set up yet. Save the mail server's settings first.")
	}
	if st.Disabled {
		return errors.New("Email is turned off. Turn it on in Integrations.")
	}
	return s.send(ctx, st, m)
}

// SendWith mails m through cfg without saving it, using password if given and
// otherwise the saved one, so a form can be tested before it is saved.
func (s *Service) SendWith(ctx context.Context, cfg Config, password *string, m Message) error {
	st, err := s.load(ctx)
	if err != nil {
		st = stored{}
	}
	// The saved password may only go to the server it was saved for. Without
	// this, a test aimed at any other host would log in there with it.
	if password == nil && st.Password != "" && !st.Config.sameServer(cfg) {
		return InputError("To test a different server, enter its password. The saved password is only used with the server it was saved for.")
	}
	st.Config = cfg
	if password != nil {
		st.Password = ""
		if *password != "" {
			if st.Password, err = s.seal(*password); err != nil {
				return err
			}
		}
	}
	return s.send(ctx, st, m)
}

func (s *Service) send(ctx context.Context, st stored, m Message) error {
	pass := ""
	if st.Password != "" {
		var err error
		if pass, err = s.open(st.Password); err != nil {
			return errors.New("The saved password can't be read by this server (the settings may have come from a backup). Enter the password again and save.")
		}
	}
	return Send(ctx, st.Config, pass, m)
}

// --- Password encryption ---

// key returns the key, making the file on first use.
func (s *Service) key(create bool) ([]byte, error) {
	b, err := os.ReadFile(s.keyPath)
	if err == nil && len(b) == 32 {
		return b, nil
	}
	if err == nil {
		return nil, errors.New("the password key file is damaged")
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) { // made a moment ago by another save
			return s.key(false)
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Service) gcm(create bool) (cipher.AEAD, error) {
	k, err := s.key(create)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

const sealedPrefix = "v1:"

func (s *Service) seal(plain string) (string, error) {
	g, err := s.gcm(true)
	if err != nil {
		return "", fmt.Errorf("can't protect the password: %w", err)
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return sealedPrefix + base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func (s *Service) open(sealed string) (string, error) {
	if !strings.HasPrefix(sealed, sealedPrefix) {
		return "", errors.New("unknown format")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, sealedPrefix))
	if err != nil {
		return "", err
	}
	g, err := s.gcm(false)
	if err != nil {
		return "", err
	}
	if len(raw) < g.NonceSize() {
		return "", errors.New("too short")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	return string(plain), err
}
