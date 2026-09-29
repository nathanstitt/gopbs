package pbs

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Auth selects an authentication method. Implementations are sealed:
// TokenAuth and PasswordAuth.
type Auth interface{ isAuth() }

// TokenAuth authenticates with an API token: AuthID is
// "user@realm!tokenname", Secret the token secret. Sent as
// "Authorization: PBSAPIToken=<authid>:<secret>" on every request.
type TokenAuth struct {
	AuthID string
	Secret string
}

func (TokenAuth) isAuth() {}

// PasswordAuth authenticates with username and password via
// /api2/json/access/ticket. Tickets are cached and renewed automatically.
type PasswordAuth struct {
	Username string // without realm
	Realm    string // e.g. "pam" or "pbs"
	Password string
}

func (PasswordAuth) isAuth() {}

func (a PasswordAuth) userID() string { return a.Username + "@" + a.Realm }

// Config configures a Client.
type Config struct {
	// BaseURL is the server address, e.g. "https://pbs.example.com:8007".
	// The scheme must be https; the port defaults to 8007.
	BaseURL string

	// Auth selects the authentication method: TokenAuth or PasswordAuth.
	Auth Auth

	// Fingerprint pins the server certificate: the SHA-256 of its DER
	// encoding as colon-separated hex (case-insensitive). When set, it is
	// always enforced and replaces chain verification. When empty, standard
	// chain verification applies.
	Fingerprint string

	// InsecureSkipAll disables certificate verification entirely. For lab
	// use only; Fingerprint is the supported way to trust a self-signed
	// server.
	InsecureSkipAll bool

	// Datastore is the target datastore's name on the server.
	Datastore string

	// Namespace within the datastore; empty for the root namespace.
	Namespace string

	// Workers is the number of concurrent chunk uploads; 0 = 4.
	Workers int

	// ChunkSizeAvg is the content-defined chunking target; 0 = 4 MiB.
	// Must be a power of two.
	ChunkSizeAvg uint64

	// Crypt enables client-side encryption (or manifest signing) with the
	// given key; nil uploads plaintext with crypt-mode "none". Treated as
	// read-only after NewClient.
	Crypt *CryptConfig
  
	// DialSession, when set, replaces the built-in TLS dial and HTTP/1.1
	// protocol upgrade: StartBackup calls it once per session and expects a
	// connection on which the backup protocol has already been negotiated —
	// the peer answered 101 Switching Protocols and now speaks HTTP/2. Use it
	// to run the session through a proxy or tunnel that performs the upgrade
	// (and holds the PBS credentials) on the client's behalf. With
	// DialSession set, BaseURL, Auth and Datastore are optional and the TLS
	// settings (Fingerprint, InsecureSkipAll) do not apply to the session.
	// StartReader does not use it: the dialer cannot tell which protocol to
	// upgrade to.
	DialSession func(ctx context.Context, ref SnapshotRef) (net.Conn, error)

	// OnUploadProgress, when set, is called by the upload pipeline as chunks
	// are committed to an index, in stream order (Stats.Size grows
	// monotonically per index), and once more with done=true after the index
	// closed. Called from the uploading goroutine; keep it fast. A v2 split
	// upload runs two indexes concurrently, so calls (for different archive
	// names) can arrive from two goroutines at once — synchronize any shared
	// state.
	OnUploadProgress func(archiveName string, stats UploadStats, done bool)
}

// SnapshotRef identifies the snapshot a backup session writes.
type SnapshotRef struct {
	Type string    // "host", "vm" or "ct"; default "host"
	ID   string    // default: os.Hostname()
	Time time.Time // default: now; fixed for the whole session
}

func (r SnapshotRef) withDefaults() (SnapshotRef, error) {
	if r.Type == "" {
		r.Type = "host"
	}
	switch r.Type {
	case "host", "vm", "ct":
	default:
		return r, fmt.Errorf("pbs: invalid backup type %q", r.Type)
	}
	if r.ID == "" {
		host, err := os.Hostname()
		if err != nil {
			return r, fmt.Errorf("pbs: no backup id and no hostname: %w", err)
		}
		r.ID = host
	}
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	return r, nil
}

// hostPort extracts the dial address from the base URL.
func hostPort(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("pbs: invalid base URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("pbs: base URL must use https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("pbs: base URL %q has no host", baseURL)
	}
	host := u.Host
	if !strings.Contains(strings.TrimPrefix(host, "["), ":") || strings.HasSuffix(host, "]") {
		host += ":8007"
	}
	return host, nil
}
