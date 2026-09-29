// Package pbstest runs an in-memory Proxmox Backup Server for tests of code
// that uses package pbs: backup and reader protocols, snapshot listing and
// namespaces, with no real server.
package pbstest

import (
	"sort"
	"testing"
	"time"

	"github.com/osshield/gopbs/internal/pbsmock"
	"github.com/osshield/gopbs/pbs"
)

const (
	authID    = "test@pbs!test"
	secret    = "secret"
	datastore = "store"
)

// Server is an in-memory PBS. A backup session becomes a snapshot only at
// Finish.
type Server struct {
	m *pbsmock.Server
}

// NewServer starts a server on a TLS listener and stops it in t.Cleanup. It
// accepts the API token "test@pbs!test" with secret "secret" and has one
// datastore, "store".
func NewServer(t testing.TB) *Server {
	t.Helper()
	m := pbsmock.New(t)
	m.Mu.Lock()
	m.Token = authID + ":" + secret
	m.Datastore = datastore
	m.Mu.Unlock()
	return &Server{m: m}
}

// Config returns a pbs.Config for this server. The caller may set
// Namespace, Crypt and Workers on it.
func (s *Server) Config() pbs.Config {
	return pbs.Config{
		BaseURL:     s.m.BaseURL,
		Auth:        pbs.TokenAuth{AuthID: authID, Secret: secret},
		Fingerprint: s.m.Fingerprint,
		Datastore:   datastore,
	}
}

// Snapshots returns the committed snapshots of all namespaces, oldest first.
func (s *Server) Snapshots() []pbs.SnapshotRef {
	s.m.Mu.Lock()
	defer s.m.Mu.Unlock()
	refs := make([]pbs.SnapshotRef, 0, len(s.m.Snapshots))
	for _, snap := range s.m.Snapshots {
		refs = append(refs, pbs.SnapshotRef{Type: snap.Type, ID: snap.ID, Time: time.Unix(snap.Time, 0)})
	}
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].Time.Before(refs[j].Time) })
	return refs
}

// DropAfterBytes closes the next backup session's connection after the
// client sent n bytes on it, to test an interrupted upload.
func (s *Server) DropAfterBytes(n int64) {
	s.m.Mu.Lock()
	s.m.DropAfter = n
	s.m.Mu.Unlock()
}

// RejectAuth makes every request answer 401.
func (s *Server) RejectAuth(on bool) {
	s.m.Mu.Lock()
	s.m.RejectAuth = on
	s.m.Mu.Unlock()
}
