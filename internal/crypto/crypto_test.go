package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// Vectors were computed independently with Python (hashlib/hmac and argon2-cffi).
func TestKeyDerivationVectors(t *testing.T) {
	const pw, salt = "Correct-Horse-Battery-1", "tester@example.com"
	b64 := base64.StdEncoding.EncodeToString

	mk, err := MakeMasterKey(pw, salt, KdfConfig{Type: KdfPBKDF2, Iterations: 600000})
	if err != nil {
		t.Fatal(err)
	}
	if got := b64(mk); got != "EpFlrO8Ym9rwQ7Uishll/mpi8fUVKbIYX5LenwOEIFM=" {
		t.Errorf("pbkdf2 master key = %s", got)
	}
	st, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if b64(st.Enc) != "RJuL9fHwbc1WCAAW3DD6scsULtSyl1chK2wiHrU0lD8=" || b64(st.Mac) != "Mp+1tAfVpP+8I9fxR2F76Z/0bi9YmSfROcL/Rz2Mj4w=" {
		t.Errorf("stretched key mismatch: %s %s", b64(st.Enc), b64(st.Mac))
	}
	h, err := MasterPasswordHash(mk, pw)
	if err != nil || h != "cp0u5xQa7iklU8E8fm6BFpz6nBsA1mfmcPlIOFD+cAA=" {
		t.Errorf("master password hash = %s (%v)", h, err)
	}
	a, err := MakeMasterKey(pw, salt, KdfConfig{Type: KdfArgon2id, Iterations: 3, Memory: 64, Parallelism: 4})
	if err != nil || b64(a) != "Y4hdXdp1+oBUhDCKKMG+ILUKYbWwpvTa7jamJX32gqE=" {
		t.Errorf("argon2id master key = %s (%v)", b64(a), err)
	}
	material := make([]byte, 16)
	for i := range material {
		material[i] = byte(i)
	}
	sk, err := DeriveSendKey(material)
	if err != nil || b64(sk.Bytes()) != "BjqVWhwBtOGqy3zTWckZssthBBwMBclMDrdvuanhRLP77KB03hQ3oaIzCtKDMTir874lYaOjCuHzPhXhovfKBA==" {
		t.Errorf("send key = %s (%v)", b64(sk.Bytes()), err)
	}
}

func TestEncStringRoundTrip(t *testing.T) {
	k := GenerateSymmetricKey()
	for _, s := range []string{"", "hello", "ünïcödé & <tags>", string(bytes.Repeat([]byte("x"), 1000))} {
		enc, err := EncryptString(k, s)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecryptToString(k, enc)
		if err != nil || dec != s {
			t.Fatalf("round trip %q -> %q (%v)", s, dec, err)
		}
		es, _ := ParseEncString(enc)
		if es.String() != enc {
			t.Fatalf("format mismatch")
		}
	}
	enc, _ := EncryptString(k, "secret")
	if _, err := DecryptToString(GenerateSymmetricKey(), enc); err == nil {
		t.Fatal("expected MAC failure with wrong key")
	}
}

func TestUserKeyUnwrap(t *testing.T) {
	mk := bytes.Repeat([]byte{7}, 32)
	st, _ := StretchMasterKey(mk)
	uk := GenerateSymmetricKey()
	wrapped, _ := Encrypt(st, uk.Bytes())
	got, err := DecryptUserKeyWithMasterKey(mk, wrapped.String())
	if err != nil || !bytes.Equal(got.Bytes(), uk.Bytes()) {
		t.Fatalf("unwrap failed: %v", err)
	}
	if _, err := DecryptUserKeyWithMasterKey(bytes.Repeat([]byte{8}, 32), wrapped.String()); err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestRSAEncapsulation(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	k := GenerateSymmetricKey()
	enc, err := EncapsulateKey(k, pub)
	if err != nil || enc[:2] != "4." {
		t.Fatalf("encapsulate: %s %v", enc, err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	p2, err := ParsePrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecapsulateKey(p2, enc)
	if err != nil || !bytes.Equal(got.Bytes(), k.Bytes()) {
		t.Fatalf("decapsulate: %v", err)
	}
}

func TestFileRoundTrip(t *testing.T) {
	k := GenerateSymmetricKey()
	data := []byte("attachment body\n")
	enc, err := EncryptFile(k, data)
	if err != nil || enc[0] != 2 {
		t.Fatalf("encrypt file: %v", err)
	}
	dec, err := DecryptFile(k, enc)
	if err != nil || !bytes.Equal(dec, data) {
		t.Fatalf("decrypt file: %v", err)
	}
	enc[len(enc)-1] ^= 1
	if _, err := DecryptFile(k, enc); err == nil {
		t.Fatal("expected MAC failure on tampered file")
	}
}
