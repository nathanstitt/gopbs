package pbs_test

import (
	"context"
	"testing"
	"time"

	"github.com/osshield/gopbs/internal/pbsmock"
	"github.com/osshield/gopbs/pbs"
)

func slowServer(t *testing.T, delay time.Duration) *pbsmock.Server {
	t.Helper()
	m := pbsmock.New(t)
	m.Mu.Lock()
	m.AnswerDelay = delay
	m.Mu.Unlock()
	return m
}

// A datastore on disks that spin down answers its first request late. With a
// ResponseTimeout above that delay, both a session and a REST request wait
// for the answer.
func TestResponseTimeoutWaitsForASlowServer(t *testing.T) {
	m := slowServer(t, 200*time.Millisecond)
	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.ResponseTimeout = 2 * time.Second })
	ctx := context.Background()

	s, err := c.StartBackup(ctx, pbs.SnapshotRef{ID: "testhost"})
	if err != nil {
		t.Fatalf("StartBackup against a slow server: %v", err)
	}
	_ = s.Abort()
	if _, err := c.ListSnapshots(ctx, "host", "testhost"); err != nil {
		t.Fatalf("ListSnapshots against a slow server: %v", err)
	}
}

// A server that answers later than ResponseTimeout is given up on, and soon.
func TestResponseTimeoutEndsAWaitThatIsTooLong(t *testing.T) {
	m := slowServer(t, 3*time.Second)
	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.ResponseTimeout = 300 * time.Millisecond })
	ctx := context.Background()

	start := time.Now()
	if _, err := c.StartBackup(ctx, pbs.SnapshotRef{ID: "testhost"}); err == nil {
		t.Fatal("StartBackup waited past ResponseTimeout")
	}
	if _, err := c.ListSnapshots(ctx, "host", "testhost"); err == nil {
		t.Fatal("ListSnapshots waited past ResponseTimeout")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the two calls took %v: ResponseTimeout did not bound them", took)
	}
}

// A session's dead-connection check (idle, then ping) spends ResponseTimeout
// in all; zero keeps the defaults.
func TestResponseTimeoutSetsTheSessionCheck(t *testing.T) {
	m := pbsmock.New(t)
	idle, ping := pbs.SessionTimeouts(clientFor(t, m, func(cfg *pbs.Config) { cfg.ResponseTimeout = 2 * time.Minute }))
	if idle+ping != 2*time.Minute || idle <= ping {
		t.Fatalf("idle %v + ping %v, want 2m in all, most of it idle", idle, ping)
	}
	idle, ping = pbs.SessionTimeouts(clientFor(t, m, nil))
	if idle != 30*time.Second || ping != 15*time.Second {
		t.Fatalf("defaults: idle %v, ping %v; want 30s and 15s", idle, ping)
	}
}
