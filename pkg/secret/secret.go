// Package secret seals small secrets (an SMTP password, a client secret) with
// AES-256-GCM, using a key kept in a file beside the database. A copy of the
// database alone, such as a backup, can't open them.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyPath is the encryption key's file, beside the database.
func KeyPath(dbPath string) string {
	return strings.TrimSuffix(dbPath, filepath.Ext(dbPath)) + "-secret.key"
}

// Box seals and opens secrets with the key in a file, making the file on first use.
type Box struct{ path string }

// NewBox returns a Box using the key file at path.
func NewBox(path string) *Box { return &Box{path: path} }

const prefix = "v1:"

func (b *Box) key(create bool) ([]byte, error) {
	k, err := os.ReadFile(b.path)
	if err == nil && len(k) == 32 {
		return k, nil
	}
	if err == nil {
		return nil, errors.New("the password key file is damaged")
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	k = make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(b.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) { // made a moment ago by someone else
			return b.key(false)
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(k); err != nil {
		return nil, err
	}
	return k, nil
}

func (b *Box) gcm(create bool) (cipher.AEAD, error) {
	k, err := b.key(create)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Path is the key file.
func (b *Box) Path() string { return b.path }

// Seal encrypts plain.
func (b *Box) Seal(plain string) (string, error) {
	g, err := b.gcm(true)
	if err != nil {
		return "", fmt.Errorf("can't protect the secret: %w", err)
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(plain), nil)), nil
}

// Open decrypts what Seal made. It fails for another server's key.
func (b *Box) Open(sealed string) (string, error) {
	if !strings.HasPrefix(sealed, prefix) {
		return "", errors.New("unknown format")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		return "", err
	}
	g, err := b.gcm(false)
	if err != nil {
		return "", err
	}
	if len(raw) < g.NonceSize() {
		return "", errors.New("too short")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	return string(plain), err
}
