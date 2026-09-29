package pbs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// canonicalManifestJSON renders the manifest in the canonical form PBS signs:
// the manifest without its "signature" and "unprotected" members, object keys
// sorted bytewise, no whitespace, serde_json string escaping. Must stay
// byte-identical to proxmox_serde's to_canonical_json or signatures diverge.
func canonicalManifestJSON(m backupManifest) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("pbs: encoding manifest: %w", err)
	}
	return canonicalManifestBytes(raw)
}

// The reader canonicalizes the manifest as received, so members this client
// does not model are still covered by the signature.
func canonicalManifestBytes(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree map[string]any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("pbs: re-reading manifest: %w", err)
	}
	delete(tree, "signature")
	delete(tree, "unprotected")

	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonicalJSON writes v as canonical JSON. Nulls and non-integer
// numbers are rejected rather than guessed at: neither occurs in a valid
// manifest, and a loud error beats a signature nobody can verify.
func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return fmt.Errorf("pbs: non-integer number %s not allowed in signed manifest", v)
		}
		buf.WriteString(string(v))
	case string:
		writeCanonicalString(buf, v)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		return fmt.Errorf("pbs: null not allowed in signed manifest")
	default:
		return fmt.Errorf("pbs: unexpected %T in manifest", v)
	}
	return nil
}

// writeCanonicalString escapes like serde_json: only the quote, backslash and
// control characters — no HTML escaping (which is where encoding/json's
// output differs), non-ASCII passed through as UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			buf.WriteString(`\"`)
		case c == '\\':
			buf.WriteString(`\\`)
		case c == '\b':
			buf.WriteString(`\b`)
		case c == '\t':
			buf.WriteString(`\t`)
		case c == '\n':
			buf.WriteString(`\n`)
		case c == '\f':
			buf.WriteString(`\f`)
		case c == '\r':
			buf.WriteString(`\r`)
		case c < 0x20:
			buf.WriteString(`\u00`)
			buf.WriteByte(hexDigits[c>>4])
			buf.WriteByte(hexDigits[c&0xf])
		default:
			buf.WriteByte(c)
		}
	}
	buf.WriteByte('"')
}
