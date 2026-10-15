package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	EncTypeAesCbc256B64                   = 0
	EncTypeAesCbc128HmacSha256B64         = 1
	EncTypeAesCbc256HmacSha256B64         = 2
	EncTypeRsa2048OaepSha256B64           = 3
	EncTypeRsa2048OaepSha1B64             = 4
	EncTypeRsa2048OaepSha256HmacSha256B64 = 5
	EncTypeRsa2048OaepSha1HmacSha256B64   = 6
	EncTypeCoseEncrypt0                   = 7
)

var ErrMacMismatch = errors.New("MAC comparison failed")

// EncString is a parsed Bitwarden "<type>.<iv>|<data>|<mac>" string.
type EncString struct {
	Type int
	IV   []byte
	Data []byte
	Mac  []byte
}

func ParseEncString(s string) (*EncString, error) {
	if s == "" {
		return nil, errors.New("empty EncString")
	}
	encType := EncTypeAesCbc256HmacSha256B64
	body := s
	if dot := strings.IndexByte(s, '.'); dot > 0 {
		t, err := strconv.Atoi(s[:dot])
		if err != nil {
			return nil, fmt.Errorf("invalid EncString type: %w", err)
		}
		encType = t
		body = s[dot+1:]
	} else if parts := strings.Split(s, "|"); len(parts) == 2 {
		encType = EncTypeAesCbc128HmacSha256B64
	} else {
		encType = EncTypeAesCbc256B64
	}
	parts := strings.Split(body, "|")
	dec := func(p string) ([]byte, error) { return base64.StdEncoding.DecodeString(p) }
	es := &EncString{Type: encType}
	var err error
	switch encType {
	case EncTypeAesCbc256B64:
		if len(parts) != 2 {
			return nil, errors.New("invalid type 0 EncString")
		}
		if es.IV, err = dec(parts[0]); err != nil {
			return nil, err
		}
		if es.Data, err = dec(parts[1]); err != nil {
			return nil, err
		}
	case EncTypeAesCbc128HmacSha256B64, EncTypeAesCbc256HmacSha256B64:
		if len(parts) != 3 {
			return nil, errors.New("invalid AES EncString")
		}
		if es.IV, err = dec(parts[0]); err != nil {
			return nil, err
		}
		if es.Data, err = dec(parts[1]); err != nil {
			return nil, err
		}
		if es.Mac, err = dec(parts[2]); err != nil {
			return nil, err
		}
	case EncTypeRsa2048OaepSha256B64, EncTypeRsa2048OaepSha1B64,
		EncTypeRsa2048OaepSha256HmacSha256B64, EncTypeRsa2048OaepSha1HmacSha256B64:
		if es.Data, err = dec(parts[0]); err != nil {
			return nil, err
		}
	case EncTypeCoseEncrypt0:
		return nil, errors.New("COSE (type 7) EncStrings are not supported")
	default:
		return nil, fmt.Errorf("unsupported EncString type %d", encType)
	}
	return es, nil
}

func (e *EncString) String() string {
	b64 := base64.StdEncoding.EncodeToString
	switch e.Type {
	case EncTypeAesCbc256B64:
		return "0." + b64(e.IV) + "|" + b64(e.Data)
	case EncTypeAesCbc128HmacSha256B64, EncTypeAesCbc256HmacSha256B64:
		return strconv.Itoa(e.Type) + "." + b64(e.IV) + "|" + b64(e.Data) + "|" + b64(e.Mac)
	default:
		return strconv.Itoa(e.Type) + "." + b64(e.Data)
	}
}

// Decrypt decrypts a symmetric EncString.
func (e *EncString) Decrypt(key *SymmetricKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("no key available to decrypt")
	}
	switch e.Type {
	case EncTypeAesCbc256B64:
		return aesCbcDecrypt(key.Enc, e.IV, e.Data)
	case EncTypeAesCbc256HmacSha256B64:
		if len(key.Mac) == 0 {
			return nil, errors.New("key has no MAC component")
		}
		m := hmac.New(sha256.New, key.Mac)
		m.Write(e.IV)
		m.Write(e.Data)
		if !hmac.Equal(m.Sum(nil), e.Mac) {
			return nil, ErrMacMismatch
		}
		return aesCbcDecrypt(key.Enc, e.IV, e.Data)
	default:
		return nil, fmt.Errorf("EncString type %d is not a symmetric type", e.Type)
	}
}

func (e *EncString) DecryptString(key *SymmetricKey) (string, error) {
	b, err := e.Decrypt(key)
	return string(b), err
}

// DecryptRSA decapsulates an RSA-OAEP EncString with a private key.
func (e *EncString) DecryptRSA(priv *rsa.PrivateKey) ([]byte, error) {
	switch e.Type {
	case EncTypeRsa2048OaepSha256B64, EncTypeRsa2048OaepSha256HmacSha256B64:
		return rsa.DecryptOAEP(sha256.New(), nil, priv, e.Data, nil)
	case EncTypeRsa2048OaepSha1B64, EncTypeRsa2048OaepSha1HmacSha256B64:
		return rsa.DecryptOAEP(sha1.New(), nil, priv, e.Data, nil)
	default:
		return nil, fmt.Errorf("EncString type %d is not an RSA type", e.Type)
	}
}

// Encrypt produces a type 2 EncString.
func Encrypt(key *SymmetricKey, plain []byte) (*EncString, error) {
	if key == nil || len(key.Mac) == 0 {
		return nil, errors.New("encryption requires a 64-byte AES-CBC-HMAC key")
	}
	iv := RandomBytes(16)
	ct, err := aesCbcEncrypt(key.Enc, iv, plain)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key.Mac)
	m.Write(iv)
	m.Write(ct)
	return &EncString{Type: EncTypeAesCbc256HmacSha256B64, IV: iv, Data: ct, Mac: m.Sum(nil)}, nil
}

func EncryptString(key *SymmetricKey, s string) (string, error) {
	es, err := Encrypt(key, []byte(s))
	if err != nil {
		return "", err
	}
	return es.String(), nil
}

// DecryptToString parses and decrypts in one step.
func DecryptToString(key *SymmetricKey, s string) (string, error) {
	es, err := ParseEncString(s)
	if err != nil {
		return "", err
	}
	return es.DecryptString(key)
}

func DecryptToKey(key *SymmetricKey, s string) (*SymmetricKey, error) {
	es, err := ParseEncString(s)
	if err != nil {
		return nil, err
	}
	b, err := es.Decrypt(key)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(b)
}

// EncapsulateKey wraps a symmetric key for an RSA public key (type 4).
func EncapsulateKey(key *SymmetricKey, publicKeyDER []byte) (string, error) {
	pubAny, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return "", err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("public key is not RSA")
	}
	ct, err := rsa.EncryptOAEP(sha1.New(), randReader{}, pub, key.Bytes(), nil)
	if err != nil {
		return "", err
	}
	return (&EncString{Type: EncTypeRsa2048OaepSha1B64, Data: ct}).String(), nil
}

// DecapsulateKey unwraps an RSA EncString into a symmetric key.
func DecapsulateKey(priv *rsa.PrivateKey, s string) (*SymmetricKey, error) {
	es, err := ParseEncString(s)
	if err != nil {
		return nil, err
	}
	b, err := es.DecryptRSA(priv)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(b)
}

func ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if k1, err1 := x509.ParsePKCS1PrivateKey(der); err1 == nil {
			return k1, nil
		}
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

func PublicKeyDER(priv *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&priv.PublicKey)
}

func aesCbcDecrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(out) {
		return nil, errors.New("invalid padding")
	}
	for _, p := range out[len(out)-pad:] {
		if int(p) != pad {
			return nil, errors.New("invalid padding")
		}
	}
	return out[:len(out)-pad], nil
}

func aesCbcEncrypt(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	buf := make([]byte, len(plain)+pad)
	copy(buf, plain)
	for i := len(plain); i < len(buf); i++ {
		buf[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)
	return buf, nil
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	copy(p, RandomBytes(len(p)))
	return len(p), nil
}
