package pbs_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/osshield/gopbs/internal/pbsmock"
	"github.com/osshield/gopbs/pbs"
)

// countingDial is a Config.Dial that counts the connections it opens.
func countingDial(n *atomic.Int32) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

// Dial opens every TCP connection: each session's upgrade and the REST API.
func TestDialOpensEveryConnection(t *testing.T) {
	m := pbsmock.New(t)
	var dials atomic.Int32
	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Dial = countingDial(&dials) })
	ctx := context.Background()

	s, err := c.StartBackup(ctx, pbs.SnapshotRef{ID: "testhost"})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Abort()
	if got := dials.Load(); got != 1 {
		t.Fatalf("StartBackup dialed %d times through Dial, want 1", got)
	}

	if _, err := c.ListSnapshots(ctx, "host", "testhost"); err != nil {
		t.Fatal(err)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("ListSnapshots did not dial through Dial (dials = %d)", got)
	}
}

// TLS still runs on a connection Dial opened, so the fingerprint pin holds.
func TestDialKeepsTheFingerprintPin(t *testing.T) {
	m := pbsmock.New(t)
	var dials atomic.Int32
	c := clientFor(t, m, func(cfg *pbs.Config) {
		cfg.Dial = countingDial(&dials)
		cfg.Fingerprint = "00" + m.Fingerprint[2:]
		if cfg.Fingerprint == m.Fingerprint {
			cfg.Fingerprint = "11" + m.Fingerprint[2:]
		}
	})
	_, err := c.StartBackup(context.Background(), pbs.SnapshotRef{ID: "testhost"})
	if !errors.Is(err, pbs.ErrFingerprint) {
		t.Fatalf("StartBackup with a wrong pin: %v, want ErrFingerprint", err)
	}
	if dials.Load() != 1 {
		t.Fatal("the connection was not opened through Dial")
	}
}

func TestDialErrorIsReturned(t *testing.T) {
	m := pbsmock.New(t)
	refused := errors.New("refused by the test dialer")
	c := clientFor(t, m, func(cfg *pbs.Config) {
		cfg.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, refused }
	})
	if _, err := c.StartBackup(context.Background(), pbs.SnapshotRef{ID: "testhost"}); !errors.Is(err, refused) {
		t.Fatalf("StartBackup: %v, want the dialer's error", err)
	}
	if _, err := c.ListSnapshots(context.Background(), "host", "testhost"); !errors.Is(err, refused) {
		t.Fatalf("ListSnapshots: %v, want the dialer's error", err)
	}
}
