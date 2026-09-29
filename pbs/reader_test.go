package pbs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/osshield/gopbs/pbs"
	"go.uber.org/goleak"
)

func backupStream(t *testing.T, c *pbs.Client, ref pbs.SnapshotRef, data, blob []byte) (pbs.SnapshotRef, pbs.UploadStats) {
	t.Helper()
	ctx := context.Background()
	s, err := c.StartBackup(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Abort()
	stats, err := s.UploadStream(ctx, "data.db", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UploadBlob(ctx, pbs.NewBlobEncoder(), "manifest.blob", blob, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	return s.Ref(), stats
}

func startReader(t *testing.T, c *pbs.Client, ref pbs.SnapshotRef) *pbs.ReaderSession {
	t.Helper()
	r, err := c.StartReader(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func readIndex(ctx context.Context, r *pbs.ReaderSession, name string) ([]byte, error) {
	rc, err := r.OpenDynamicIndex(ctx, name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func TestReaderRoundTrip(t *testing.T) {
	data := append(randomBytes(900_000), bytes.Repeat([]byte("repeated tail "), 50_000)...)
	blob := []byte(`{"org":"example","tables":3}`)
	key := testKey(t)

	for _, tc := range []struct {
		name    string
		crypt   *pbs.CryptConfig
		workers int
	}{
		{"none", nil, 0},
		{"none serial", nil, 1},
		{"encrypt", &pbs.CryptConfig{Mode: pbs.CryptModeEncrypt, Key: key}, 3},
		{"sign-only", &pbs.CryptConfig{Mode: pbs.CryptModeSignOnly, Key: key}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockPBS(t)
			m.setCryptKey(key)
			c := clientFor(t, m, func(c *pbs.Config) {
				c.Crypt = tc.crypt
				c.Workers = tc.workers
				c.ChunkSizeAvg = 64 << 10
			})
			ref, stats := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, data, blob)
			if stats.ChunkCount < 4 {
				t.Fatalf("want several chunks, got %d", stats.ChunkCount)
			}

			r := startReader(t, c, ref)
			ctx := context.Background()
			man, err := r.Manifest(ctx)
			if err != nil {
				t.Fatal(err)
			}
			names := map[string]string{}
			for _, f := range man.Files {
				names[f.Filename] = f.CryptMode
			}
			wantMode := "none"
			if tc.crypt != nil {
				wantMode = string(tc.crypt.Mode)
			}
			if names["data.db.didx"] != wantMode || names["manifest.blob"] != wantMode {
				t.Fatalf("manifest files: %v", names)
			}

			gotBlob, err := r.DownloadBlob(ctx, "manifest.blob")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotBlob, blob) {
				t.Fatalf("blob = %q", gotBlob)
			}
			got, err := readIndex(ctx, r, "data.db")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("stream differs: %d bytes, want %d", len(got), len(data))
			}
		})
	}
}

func TestUploadStreamNewBytes(t *testing.T) {
	m := newMockPBS(t)
	c := clientFor(t, m, func(c *pbs.Config) { c.ChunkSizeAvg = 64 << 10 })
	data := randomBytes(500_000)

	at := time.Unix(1_700_000_000, 0)
	_, first := backupStream(t, c, pbs.SnapshotRef{ID: "org1", Time: at}, data, []byte("{}"))
	if first.NewBytes != uint64(len(data)) || first.Size != uint64(len(data)) {
		t.Fatalf("first backup: %+v", first)
	}
	_, second := backupStream(t, c, pbs.SnapshotRef{ID: "org1", Time: at.Add(time.Hour)}, data, []byte("{}"))
	if second.NewBytes != 0 || second.NewChunks != 0 || second.ReusedChunks != second.ChunkCount {
		t.Fatalf("second backup should deduplicate against the first: %+v", second)
	}
}

func TestReaderTamperedChunk(t *testing.T) {
	m := newMockPBS(t)
	c := clientFor(t, m, func(c *pbs.Config) { c.ChunkSizeAvg = 64 << 10 })
	ref, stats := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(400_000), []byte("{}"))

	// Fix the CRC so only the digest check can notice.
	m.mu.Lock()
	for d, framed := range m.chunksEncoded {
		if d != hexDigest(stats.Entries[1].Digest) {
			continue
		}
		framed[len(framed)-1] ^= 0xff
		fixCRC(framed)
	}
	m.mu.Unlock()

	_, err := readIndex(context.Background(), startReader(t, c, ref), "data.db")
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("err = %v, want digest mismatch", err)
	}
}

func TestReaderWrongKey(t *testing.T) {
	key := testKey(t)
	m := newMockPBS(t)
	m.setCryptKey(key)
	c := clientFor(t, m, func(c *pbs.Config) { c.Crypt = &pbs.CryptConfig{Key: key} })
	ref, _ := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(10_000), []byte("{}"))

	other := key
	other[0] ^= 1
	wrong := clientFor(t, m, func(c *pbs.Config) { c.Crypt = &pbs.CryptConfig{Key: other} })
	_, err := startReader(t, wrong, ref).Manifest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("err = %v, want wrong key", err)
	}

	// An unencrypted reader can list the files but not decrypt them.
	plain := startReader(t, clientFor(t, m, nil), ref)
	if _, err := plain.Manifest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := readIndex(context.Background(), plain, "data.db"); err == nil {
		t.Fatal("encrypted index read without a key")
	}
}

func TestReaderForgedManifest(t *testing.T) {
	key := testKey(t)
	m := newMockPBS(t)
	c := clientFor(t, m, func(c *pbs.Config) { c.Crypt = &pbs.CryptConfig{Mode: pbs.CryptModeSignOnly, Key: key} })
	ref, _ := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(10_000), []byte("{}"))

	m.mu.Lock()
	snap := m.snapshots[0]
	framed := snap.files["index.json.blob"]
	manifest := bytes.Replace(framed[12:], []byte(`"size":10000`), []byte(`"size":10001`), 1)
	if bytes.Equal(manifest, framed[12:]) {
		m.mu.Unlock()
		t.Fatal("test setup: size not found in manifest")
	}
	snap.files["index.json.blob"] = pbs.NewBlobEncoder().Encode(manifest, false)
	m.mu.Unlock()

	_, err := startReader(t, c, ref).Manifest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Fatalf("err = %v, want signature mismatch", err)
	}
}

func TestReaderNotFound(t *testing.T) {
	m := newMockPBS(t)
	c := clientFor(t, m, nil)
	ref, _ := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(10_000), []byte("{}"))

	missing := ref
	missing.Time = ref.Time.Add(-time.Hour)
	if _, err := c.StartReader(context.Background(), missing); !errors.Is(err, pbs.ErrNotFound) {
		t.Fatalf("unknown snapshot: err = %v", err)
	}

	r := startReader(t, c, ref)
	if _, err := r.DownloadBlob(context.Background(), "nope.blob"); !errors.Is(err, pbs.ErrNotFound) {
		t.Fatalf("unknown blob: err = %v", err)
	}
	if _, err := r.OpenDynamicIndex(context.Background(), "nope"); !errors.Is(err, pbs.ErrNotFound) {
		t.Fatalf("unknown index: err = %v", err)
	}
}

func TestReaderRequiresTime(t *testing.T) {
	m := newMockPBS(t)
	if _, err := clientFor(t, m, nil).StartReader(context.Background(), pbs.SnapshotRef{ID: "x"}); err == nil {
		t.Fatal("reader without a backup time must fail")
	}
}

func TestReaderCancel(t *testing.T) {
	m := newMockPBS(t)
	c := clientFor(t, m, func(c *pbs.Config) { c.ChunkSizeAvg = 64 << 10 })
	ref, _ := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(2_000_000), []byte("{}"))

	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	r, err := c.StartReader(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := r.OpenDynamicIndex(ctx, "data.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(rc)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not stop after cancel")
	}
	rc.Close()
}

func TestAuthRejected(t *testing.T) {
	m := newMockPBS(t)
	c := clientFor(t, m, nil)
	ref, _ := backupStream(t, c, pbs.SnapshotRef{ID: "org1"}, randomBytes(1000), []byte("{}"))
	m.mu.Lock()
	m.rejectAuth = true
	m.mu.Unlock()

	ctx := context.Background()
	_, errBackup := c.StartBackup(ctx, pbs.SnapshotRef{ID: "org1"})
	_, errReader := c.StartReader(ctx, ref)
	_, errList := c.ListSnapshots(ctx, "", "org1")
	for name, err := range map[string]error{"backup": errBackup, "reader": errReader, "list": errList} {
		if !errors.Is(err, pbs.ErrAuth) {
			t.Errorf("%s: err = %v, want ErrAuth", name, err)
			continue
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: error leaks the secret: %v", name, err)
		}
	}

	pw := clientFor(t, m, func(c *pbs.Config) {
		c.Auth = pbs.PasswordAuth{Username: "user", Realm: "pam", Password: "hunter2"}
	})
	_, err := pw.ListSnapshots(ctx, "", "org1")
	if !errors.Is(err, pbs.ErrAuth) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("password login: err = %v", err)
	}
}

func TestDecodeBlob(t *testing.T) {
	key := testKey(t)
	cfg := &pbs.CryptConfig{Key: key}
	enc := pbs.NewBlobEncoder()
	plain := bytes.Repeat([]byte("blob content "), 1000)
	random := randomBytes(4000)

	encrypted, err := enc.EncodeEncrypted(plain, true, cfg)
	if err != nil {
		t.Fatal(err)
	}
	encryptedRaw, err := enc.EncodeEncrypted(random, false, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		framed []byte
		want   []byte
	}{
		{"uncompressed", append([]byte(nil), enc.Encode(plain, false)...), plain},
		{"compressed", append([]byte(nil), enc.Encode(plain, true)...), plain},
		{"encrypted", encryptedRaw, random},
		{"encrypted compressed", encrypted, plain},
	} {
		got, err := pbs.DecodeBlob(tc.framed, cfg)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("%s: content differs", tc.name)
		}
	}

	if _, err := pbs.DecodeBlob(encrypted, nil); err == nil {
		t.Fatal("encrypted blob decoded without a key")
	}
	bad := append([]byte(nil), enc.Encode(plain, false)...)
	bad[20] ^= 1
	if _, err := pbs.DecodeBlob(bad, nil); err == nil || !strings.Contains(err.Error(), "crc") {
		t.Fatalf("bad crc: err = %v", err)
	}
}
