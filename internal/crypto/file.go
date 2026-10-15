package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// DecryptFile decrypts an EncArrayBuffer: [type][iv 16][mac 32][ciphertext].
func DecryptFile(key *SymmetricKey, buf []byte) ([]byte, error) {
	if len(buf) < 1 {
		return nil, errors.New("empty encrypted file")
	}
	switch buf[0] {
	case EncTypeAesCbc256HmacSha256B64:
		if len(buf) < 1+16+32+16 {
			return nil, errors.New("encrypted file too short")
		}
		iv, mac, ct := buf[1:17], buf[17:49], buf[49:]
		m := hmac.New(sha256.New, key.Mac)
		m.Write(iv)
		m.Write(ct)
		if !hmac.Equal(m.Sum(nil), mac) {
			return nil, ErrMacMismatch
		}
		return aesCbcDecrypt(key.Enc, iv, ct)
	case EncTypeAesCbc256B64:
		if len(buf) < 1+16+16 {
			return nil, errors.New("encrypted file too short")
		}
		return aesCbcDecrypt(key.Enc, buf[1:17], buf[17:])
	default:
		return nil, errors.New("unsupported encrypted file type")
	}
}

// EncryptFile produces a type 2 EncArrayBuffer.
func EncryptFile(key *SymmetricKey, plain []byte) ([]byte, error) {
	es, err := Encrypt(key, plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+16+32+len(es.Data))
	out = append(out, EncTypeAesCbc256HmacSha256B64)
	out = append(out, es.IV...)
	out = append(out, es.Mac...)
	out = append(out, es.Data...)
	return out, nil
}
