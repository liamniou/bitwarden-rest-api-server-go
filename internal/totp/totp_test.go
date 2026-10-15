package totp

import (
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA-1, 8 digits) plus Bitwarden URI forms.
func TestGenerate(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	cases := []struct {
		key  string
		unix int64
		want string
	}{
		{"otpauth://totp/x?secret=" + secret + "&digits=8", 59, "94287082"},
		{"otpauth://totp/x?secret=" + secret + "&digits=8", 1111111109, "07081804"},
		{"otpauth://totp/x?secret=" + secret + "&digits=8", 20000000000, "65353130"},
		{secret, 59, "287082"},
		{"gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 59, "287082"},
	}
	for _, c := range cases {
		got, err := Generate(c.key, time.Unix(c.unix, 0))
		if err != nil || got != c.want {
			t.Errorf("Generate(%q, %d) = %q, %v; want %q", c.key, c.unix, got, err, c.want)
		}
	}
	steam, err := Generate("steam://"+secret, time.Unix(59, 0))
	if err != nil || len(steam) != 5 {
		t.Errorf("steam code %q %v", steam, err)
	}
	if _, err := Generate("not base32!!", time.Now()); err == nil {
		t.Error("expected error for invalid secret")
	}
}
