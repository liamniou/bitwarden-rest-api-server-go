// Package totp generates TOTP codes from Bitwarden login TOTP values.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const steamChars = "23456789BCDFGHJKMNPQRTVWXY"

// Generate returns the current code for a raw secret, otpauth:// or steam:// URI.
func Generate(key string, now time.Time) (string, error) {
	key = strings.TrimSpace(key)
	algo := sha1.New
	digits, period := 6, 30
	steam := false
	secret := key

	lower := strings.ToLower(key)
	switch {
	case strings.HasPrefix(lower, "otpauth://"):
		u, err := url.Parse(key)
		if err != nil {
			return "", err
		}
		q := u.Query()
		secret = q.Get("secret")
		if d, err := strconv.Atoi(q.Get("digits")); err == nil && d > 0 {
			if d > 10 {
				d = 10
			}
			digits = d
		}
		if p, err := strconv.Atoi(q.Get("period")); err == nil && p > 0 {
			period = p
		}
		switch strings.ToLower(q.Get("algorithm")) {
		case "sha256":
			algo = sha256.New
		case "sha512":
			algo = sha512.New
		}
		if strings.EqualFold(q.Get("issuer"), "steam") || strings.EqualFold(q.Get("encoder"), "steam") {
			steam = true
		}
	case strings.HasPrefix(lower, "steam://"):
		secret = key[len("steam://"):]
		steam = true
	}
	if steam {
		digits = 5
	}
	k, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return code(k, algo, digits, period, steam, now), nil
}

func decodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	if s == "" {
		return nil, errors.New("empty secret")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func code(key []byte, algo func() hash.Hash, digits, period int, steam bool, now time.Time) string {
	counter := uint64(now.Unix() / int64(period))
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(algo, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	if steam {
		out := make([]byte, digits)
		for i := range out {
			out[i] = steamChars[bin%uint32(len(steamChars))]
			bin /= uint32(len(steamChars))
		}
		return string(out)
	}
	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	s := strconv.FormatUint(uint64(bin)%mod, 10)
	for len(s) < digits {
		s = "0" + s
	}
	return s
}
