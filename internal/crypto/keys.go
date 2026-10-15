// Package crypto implements the subset of the Bitwarden client cryptography
// needed by the Vault Management API: key derivation, EncString handling and
// encrypted file blobs.
package crypto

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	KdfPBKDF2   = 0
	KdfArgon2id = 1
)

// KdfConfig mirrors the KDF parameters returned by the identity server.
type KdfConfig struct {
	Type        int
	Iterations  int
	Memory      int // MiB, Argon2id only
	Parallelism int // Argon2id only
}

// SymmetricKey is an AES-256-CBC + HMAC-SHA256 key pair (64 bytes) or, for
// legacy type-0 data, a bare 32-byte AES key with no MAC.
type SymmetricKey struct {
	Enc []byte
	Mac []byte
}

func NewSymmetricKey(b []byte) (*SymmetricKey, error) {
	switch len(b) {
	case 64:
		return &SymmetricKey{Enc: clone(b[:32]), Mac: clone(b[32:])}, nil
	case 32:
		return &SymmetricKey{Enc: clone(b)}, nil
	default:
		return nil, fmt.Errorf("unsupported symmetric key length %d (COSE/XChaCha20 keys are not supported)", len(b))
	}
}

// GenerateSymmetricKey returns a fresh random 64-byte AES-CBC-HMAC key.
func GenerateSymmetricKey() *SymmetricKey {
	k, _ := NewSymmetricKey(RandomBytes(64))
	return k
}

func (k *SymmetricKey) Bytes() []byte {
	return append(clone(k.Enc), k.Mac...)
}

func (k *SymmetricKey) B64() string {
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// NormalizeEmail produces the salt the clients use for master key derivation.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// MakeMasterKey derives the 32-byte master key from the master password.
func MakeMasterKey(password, salt string, kdf KdfConfig) ([]byte, error) {
	switch kdf.Type {
	case KdfPBKDF2:
		if kdf.Iterations < 1 {
			return nil, errors.New("invalid PBKDF2 iterations")
		}
		return pbkdf2.Key(sha256.New, password, []byte(salt), kdf.Iterations, 32)
	case KdfArgon2id:
		if kdf.Iterations < 1 || kdf.Memory < 1 || kdf.Parallelism < 1 {
			return nil, errors.New("invalid Argon2id parameters")
		}
		saltHash := sha256.Sum256([]byte(salt))
		return argon2.IDKey([]byte(password), saltHash[:], uint32(kdf.Iterations),
			uint32(kdf.Memory*1024), uint8(kdf.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type %d", kdf.Type)
	}
}

// StretchMasterKey expands a 32-byte master key into an enc/mac key pair.
func StretchMasterKey(masterKey []byte) (*SymmetricKey, error) {
	enc, err := hkdf.Expand(sha256.New, masterKey, "enc", 32)
	if err != nil {
		return nil, err
	}
	mac, err := hkdf.Expand(sha256.New, masterKey, "mac", 32)
	if err != nil {
		return nil, err
	}
	return &SymmetricKey{Enc: enc, Mac: mac}, nil
}

// MasterPasswordHash is the server authentication hash sent on password login.
func MasterPasswordHash(masterKey []byte, password string) (string, error) {
	h, err := pbkdf2.Key(sha256.New, string(masterKey), []byte(password), 1, 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h), nil
}

// ErrInvalidPassword uses the exact message the SDK-based CLI returns for a wrong password.
var ErrInvalidPassword = errors.New("Cryptography error, The decryption operation failed")

// DecryptUserKeyWithMasterKey unwraps the user key, accepting both the
// stretched (type 2) and legacy unstretched (type 0) wrapping.
func DecryptUserKeyWithMasterKey(masterKey []byte, encUserKey string) (*SymmetricKey, error) {
	es, err := ParseEncString(encUserKey)
	if err != nil {
		return nil, err
	}
	var wrapping *SymmetricKey
	if es.Type == EncTypeAesCbc256B64 {
		wrapping = &SymmetricKey{Enc: masterKey}
	} else {
		wrapping, err = StretchMasterKey(masterKey)
		if err != nil {
			return nil, err
		}
	}
	raw, err := es.Decrypt(wrapping)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	return NewSymmetricKey(raw)
}

// DeriveSendKey derives the 64-byte Send key from its 16-byte key material.
func DeriveSendKey(material []byte) (*SymmetricKey, error) {
	b, err := hkdf.Key(sha256.New, material, []byte("bitwarden-send"), "send", 64)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(b)
}

// SendPasswordHash derives the access password hash stored on the server.
func SendPasswordHash(password string, keyMaterial []byte) (string, error) {
	h, err := pbkdf2.Key(sha256.New, password, keyMaterial, 100000, 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h), nil
}

// HKDFExpandSHA256 exposes HKDF-Expand for fingerprint generation.
func HKDFExpandSHA256(prk []byte, info string, n int) ([]byte, error) {
	return hkdf.Expand(sha256.New, prk, info, n)
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
