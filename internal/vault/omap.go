package vault

import (
	"encoding/json"
	"math"
	"strconv"
	"time"
	"unicode/utf8"
)

// OMap is a JSON object that preserves insertion order, used to emit
// responses with the same key order as the Bitwarden CLI.
type OMap struct {
	keys []string
	vals map[string]any
}

func NewOMap() *OMap { return &OMap{vals: make(map[string]any, 8)} }

func (m *OMap) Set(k string, v any) *OMap {
	if _, ok := m.vals[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.vals[k] = v
	return m
}

func (m *OMap) Get(k string) any { return m.vals[k] }

func (m *OMap) MarshalJSON() ([]byte, error) { return AppendJSON(nil, m) }

// AppendJSON serializes v in a single pass, escaping strings exactly like
// JavaScript's JSON.stringify (no HTML escaping, U+2028/2029 left as is).
func AppendJSON(buf []byte, v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return append(buf, "null"...), nil
	case *OMap:
		if t == nil {
			return append(buf, "null"...), nil
		}
		buf = append(buf, '{')
		for i, k := range t.keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendString(buf, k)
			buf = append(buf, ':')
			var err error
			if buf, err = AppendJSON(buf, t.vals[k]); err != nil {
				return nil, err
			}
		}
		return append(buf, '}'), nil
	case []*OMap:
		buf = append(buf, '[')
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			var err error
			if buf, err = AppendJSON(buf, e); err != nil {
				return nil, err
			}
		}
		return append(buf, ']'), nil
	case []any:
		buf = append(buf, '[')
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			var err error
			if buf, err = AppendJSON(buf, e); err != nil {
				return nil, err
			}
		}
		return append(buf, ']'), nil
	case []string:
		buf = append(buf, '[')
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = appendString(buf, e)
		}
		return append(buf, ']'), nil
	case string:
		return appendString(buf, t), nil
	case bool:
		return strconv.AppendBool(buf, t), nil
	case int:
		return strconv.AppendInt(buf, int64(t), 10), nil
	case int64:
		return strconv.AppendInt(buf, t, 10), nil
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return append(buf, "null"...), nil
		}
		return strconv.AppendFloat(buf, t, 'f', -1, 64), nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return append(buf, b...), nil
	}
}

const hexDigits = "0123456789abcdef"

func appendString(buf []byte, s string) []byte {
	buf = append(buf, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			buf = append(buf, s[start:i]...)
			switch c {
			case '"', '\\':
				buf = append(buf, '\\', c)
			case '\n':
				buf = append(buf, '\\', 'n')
			case '\r':
				buf = append(buf, '\\', 'r')
			case '\t':
				buf = append(buf, '\\', 't')
			case '\b':
				buf = append(buf, '\\', 'b')
			case '\f':
				buf = append(buf, '\\', 'f')
			default:
				buf = append(buf, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			buf = append(buf, s[start:i]...)
			buf = append(buf, `\ufffd`...)
			i++
			start = i
			continue
		}
		i += size
	}
	buf = append(buf, s[start:]...)
	return append(buf, '"')
}

// JSTime formats a timestamp like JavaScript's Date.toJSON().
func JSTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func ParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, *s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func strPtr(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullable(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
