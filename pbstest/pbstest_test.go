package pbstest_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/pbstest"
)

func newClient(t *testing.T, cfg pbs.Config) *pbs.Client {
	t.Helper()
	c, err := pbs.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	rand.New(rand.NewSource(1)).Read(buf)
	return buf
}

func TestRoundTrip(t *testing.T) {
	srv := pbstest.NewServer(t)
	key, err := pbs.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := srv.Config()
	cfg.Namespace = "org"
	cfg.Crypt = &pbs.CryptConfig{Key: key}
	cfg.ChunkSizeAvg = 64 << 10
	c := newClient(t, cfg)
	ctx := context.Background()
	data := randomBytes(500_000)

	s, err := c.StartBackup(ctx, pbs.SnapshotRef{ID: "org1"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Abort()
	if _, err := s.UploadStream(ctx, "data.db", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if err := s.UploadBlob(ctx, pbs.NewBlobEncoder(), "manifest.blob", []byte("{}"), true); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx); err != nil {
		t.Fatal(err)
	}

	snaps := srv.Snapshots()
	if len(snaps) != 1 || snaps[0].ID != "org1" || !snaps[0].Time.Equal(s.Ref().Time.Truncate(1e9)) {
		t.Fatalf("Snapshots() = %+v", snaps)
	}
	list, err := c.ListSnapshots(ctx, "", "org1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSnapshots = %+v, %v", list, err)
	}

	r, err := c.StartReader(ctx, list[0].Ref)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rc, err := r.OpenDynamicIndex(ctx, "data.db")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("restored stream differs")
	}
}

func TestDropAfterBytes(t *testing.T) {
	srv := pbstest.NewServer(t)
	c := newClient(t, srv.Config())
	ctx := context.Background()
	srv.DropAfterBytes(64 << 10)

	s, err := c.StartBackup(ctx, pbs.SnapshotRef{ID: "org1"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Abort()
	s.UploadStream(ctx, "data.db", bytes.NewReader(randomBytes(1<<20)))
	if err := s.Finish(ctx); err == nil {
		t.Fatal("Finish after the connection dropped must fail")
	}
	if snaps := srv.Snapshots(); len(snaps) != 0 {
		t.Fatalf("interrupted backup left %+v", snaps)
	}
}

func TestAuth(t *testing.T) {
	srv := pbstest.NewServer(t)
	ctx := context.Background()

	wrong := srv.Config()
	wrong.Auth = pbs.TokenAuth{AuthID: "test@pbs!test", Secret: "not-the-secret"}
	if _, err := newClient(t, wrong).ListSnapshots(ctx, "", "x"); !errors.Is(err, pbs.ErrAuth) {
		t.Fatalf("wrong secret: err = %v", err)
	}

	srv.RejectAuth(true)
	_, err := newClient(t, srv.Config()).StartBackup(ctx, pbs.SnapshotRef{ID: "x"})
	if !errors.Is(err, pbs.ErrAuth) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("RejectAuth: err = %v", err)
	}
}

func TestUnknownDatastore(t *testing.T) {
	srv := pbstest.NewServer(t)
	cfg := srv.Config()
	cfg.Datastore = "other"
	if _, err := newClient(t, cfg).ListSnapshots(context.Background(), "", "x"); !errors.Is(err, pbs.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
