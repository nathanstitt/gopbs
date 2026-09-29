package pbs_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"slices"
	"testing"
	"time"

	"github.com/osshield/gopbs/pbs"
)

func hexDigest(d [32]byte) string { return hex.EncodeToString(d[:]) }

// fixCRC works on unencrypted frames only.
func fixCRC(framed []byte) {
	binary.LittleEndian.PutUint32(framed[8:12], crc32.ChecksumIEEE(framed[12:]))
}

func TestListSnapshots(t *testing.T) {
	m := newMockPBS(t)
	root := clientFor(t, m, nil)
	inNS := clientFor(t, m, func(c *pbs.Config) { c.Namespace = "tenant/a" })

	base := time.Unix(1_700_000_000, 0)
	backup := func(c *pbs.Client, id string, at time.Time) {
		t.Helper()
		s, err := c.StartBackup(context.Background(), pbs.SnapshotRef{ID: id, Time: at})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Abort()
		if _, err := s.UploadStream(context.Background(), "data.db", bytes.NewReader([]byte("content"))); err != nil {
			t.Fatal(err)
		}
		if err := s.Finish(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	backup(root, "org1", base)
	backup(root, "org1", base.Add(2*time.Hour))
	backup(root, "org1", base.Add(time.Hour))
	backup(root, "org2", base.Add(3*time.Hour))
	backup(inNS, "org1", base.Add(4*time.Hour))

	list, err := root.ListSnapshots(context.Background(), "", "org1")
	if err != nil {
		t.Fatal(err)
	}
	var times []time.Time
	for _, s := range list {
		times = append(times, s.Ref.Time)
		if s.Ref.Type != "host" || s.Ref.ID != "org1" {
			t.Fatalf("unexpected snapshot %+v", s.Ref)
		}
		if !slices.Contains(s.Files, "data.db.didx") || !slices.Contains(s.Files, "index.json.blob") || s.Size == 0 {
			t.Fatalf("snapshot info %+v", s)
		}
	}
	want := []time.Time{base.Add(2 * time.Hour), base.Add(time.Hour), base}
	if !slices.EqualFunc(times, want, time.Time.Equal) {
		t.Fatalf("times = %v, want newest first %v", times, want)
	}

	list, err = inNS.ListSnapshots(context.Background(), "host", "org1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || !list[0].Ref.Time.Equal(base.Add(4*time.Hour)) {
		t.Fatalf("namespace listing = %+v", list)
	}
	m.mu.Lock()
	for _, req := range m.upgradeReqs {
		if req.URL.Query().Get("ns") != "" && req.URL.Query().Get("ns") != "tenant/a" {
			t.Errorf("upgrade with ns %q", req.URL.Query().Get("ns"))
		}
	}
	m.mu.Unlock()
}

func TestInterruptedBackupLeavesNoSnapshot(t *testing.T) {
	m := newMockPBS(t)
	c := clientFor(t, m, nil)
	ctx := context.Background()
	s := start(t, c)
	defer s.Abort()
	if _, err := s.UploadStream(ctx, "data.db", bytes.NewReader(randomBytes(10_000))); err != nil {
		t.Fatal(err)
	}
	m.dropSessions()
	time.Sleep(50 * time.Millisecond)

	if err := s.Finish(ctx); err == nil {
		t.Fatal("Finish after connection drop must fail")
	}
	list, err := c.ListSnapshots(ctx, "", s.Ref().ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("interrupted backup left snapshots: %+v", list)
	}
}
