package pbs

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	// ErrAuth reports HTTP 401 or 403.
	ErrAuth = errors.New("pbs: authentication failed")

	// ErrNotFound reports an unknown datastore, snapshot or file.
	ErrNotFound = errors.New("pbs: not found")

	// ErrFingerprint reports a certificate that does not match
	// Config.Fingerprint.
	ErrFingerprint = errors.New("pbs: certificate fingerprint mismatch")
)

// Auth failures leave out the body: a server may echo the credentials.
func statusError(op, status string, code int, body []byte) error {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s: %s", ErrAuth, op, status)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s: %s: %s", ErrNotFound, op, status, strings.TrimSpace(string(body)))
	}
	return fmt.Errorf("pbs: %s: %s: %s", op, status, strings.TrimSpace(string(body)))
}
