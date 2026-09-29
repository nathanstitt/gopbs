package pbs

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// newTLSConfig builds the client TLS configuration. A fingerprint pin, when
// present, is enforced unconditionally: chain verification is skipped and the
// leaf certificate's SHA-256 must match — there is no configuration in which
// a supplied pin goes unchecked. (The reference client's pin check was dead
// code; see ARCHITECTURE.md §12.)
func newTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.Fingerprint == "" {
		return &tls.Config{InsecureSkipVerify: cfg.InsecureSkipAll}, nil
	}

	pin, err := parseFingerprint(cfg.Fingerprint)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		InsecureSkipVerify: true, // pin replaces chain verification
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("pbs: server presented no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if got != pin {
				return fmt.Errorf("%w: server has %s", ErrFingerprint, formatFingerprint(got))
			}
			return nil
		},
	}, nil
}

func parseFingerprint(s string) ([32]byte, error) {
	var pin [32]byte
	clean := strings.ToLower(strings.ReplaceAll(s, ":", ""))
	raw, err := hex.DecodeString(clean)
	if err != nil || len(raw) != 32 {
		return pin, fmt.Errorf("pbs: fingerprint must be 32 hex bytes (sha256), got %q", s)
	}
	copy(pin[:], raw)
	return pin, nil
}

func formatFingerprint(sum [32]byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(parts, ":")
}
