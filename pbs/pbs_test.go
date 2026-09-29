package pbs_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/osshield/gopbs/internal/pbsmock"
	"github.com/osshield/gopbs/pbs"
)

func clientFor(t *testing.T, m *pbsmock.Server, mutate func(*pbs.Config)) *pbs.Client {
	t.Helper()
	cfg := pbs.Config{
		BaseURL:     m.BaseURL,
		Auth:        pbs.TokenAuth{AuthID: "user@pam!token", Secret: "s3cret"},
		Fingerprint: m.Fingerprint,
		Datastore:   "store1",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := pbs.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func start(t *testing.T, c *pbs.Client) *pbs.BackupSession {
	t.Helper()
	s, err := c.StartBackup(context.Background(), pbs.SnapshotRef{ID: "testhost"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFingerprintPinning(t *testing.T) {
	m := pbsmock.New(t)

	t.Run("correct pin connects", func(t *testing.T) {
		s := start(t, clientFor(t, m, nil))
		s.Abort()
	})

	t.Run("colon-and-case formatting accepted", func(t *testing.T) {
		formatted := strings.ToUpper(m.Fingerprint[:2]) + ":" + strings.Join(splitPairs(m.Fingerprint[2:]), ":")
		s := start(t, clientFor(t, m, func(c *pbs.Config) { c.Fingerprint = formatted }))
		s.Abort()
	})

	t.Run("wrong pin rejected", func(t *testing.T) {
		bad := "00" + m.Fingerprint[2:]
		c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Fingerprint = bad })
		if _, err := c.StartBackup(context.Background(), pbs.SnapshotRef{ID: "x"}); !errors.Is(err, pbs.ErrFingerprint) {
			t.Fatalf("err = %v, want ErrFingerprint", err)
		}
		if _, err := c.ListSnapshots(context.Background(), "", "x"); !errors.Is(err, pbs.ErrFingerprint) {
			t.Fatalf("list: err = %v, want ErrFingerprint", err)
		}
	})

	t.Run("no pin fails chain verification", func(t *testing.T) {
		c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Fingerprint = "" })
		if _, err := c.StartBackup(context.Background(), pbs.SnapshotRef{ID: "x"}); err == nil {
			t.Fatal("self-signed cert must fail without a pin")
		}
	})

	t.Run("insecure skip-all connects", func(t *testing.T) {
		c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Fingerprint = ""; cfg.InsecureSkipAll = true })
		start(t, c).Abort()
	})

	t.Run("malformed pin rejected at NewClient", func(t *testing.T) {
		_, err := pbs.NewClient(pbs.Config{
			BaseURL: m.BaseURL, Auth: pbs.TokenAuth{}, Datastore: "d", Fingerprint: "nothex",
		})
		if err == nil {
			t.Fatal("malformed fingerprint must be rejected")
		}
	})
}

func splitPairs(s string) []string {
	var out []string
	for i := 0; i+1 < len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return out
}

func TestTokenAuthHeader(t *testing.T) {
	m := pbsmock.New(t)
	start(t, clientFor(t, m, nil)).Abort()

	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.UpgradeReqs) != 1 {
		t.Fatalf("%d upgrade requests", len(m.UpgradeReqs))
	}
	req := m.UpgradeReqs[0]
	if got := req.Header.Get("Authorization"); got != "PBSAPIToken=user@pam!token:s3cret" {
		t.Errorf("Authorization = %q", got)
	}
	if req.Host == "" {
		t.Error("upgrade request must carry a Host header")
	}
	q := req.URL.Query()
	if q.Get("store") != "store1" || q.Get("backup-type") != "host" || q.Get("backup-id") != "testhost" {
		t.Errorf("upgrade query = %v", q)
	}
	if q.Get("backup-time") == "" {
		t.Error("backup-time missing")
	}
}

func TestNamespaceParameter(t *testing.T) {
	m := pbsmock.New(t)
	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Namespace = "prod/db" })
	start(t, c).Abort()

	m.Mu.Lock()
	defer m.Mu.Unlock()
	if got := m.UpgradeReqs[0].URL.Query().Get("ns"); got != "prod/db" {
		t.Errorf("ns = %q", got)
	}
}

func TestPasswordAuth(t *testing.T) {
	m := pbsmock.New(t)
	c := clientFor(t, m, func(cfg *pbs.Config) {
		cfg.Auth = pbs.PasswordAuth{Username: "user", Realm: "pam", Password: "hunter2"}
	})

	start(t, c).Abort()
	start(t, c).Abort() // ticket must be cached, not re-requested

	m.Mu.Lock()
	loginCount := m.LoginCount
	cookie := m.UpgradeReqs[0].Header.Get("Cookie")
	m.Mu.Unlock()
	if loginCount != 1 {
		t.Errorf("login count = %d, want 1 (ticket cached)", loginCount)
	}
	if !strings.Contains(cookie, "PBSAuthCookie=PBS%3Auser%40pam%3ATICKETDATA%3D%3D") {
		t.Errorf("Cookie = %q", cookie)
	}

	// Wrong password surfaces the server response.
	bad := clientFor(t, m, func(cfg *pbs.Config) {
		cfg.Auth = pbs.PasswordAuth{Username: "user", Realm: "pam", Password: "wrong"}
	})
	if _, err := bad.StartBackup(context.Background(), pbs.SnapshotRef{ID: "x"}); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Errorf("wrong password: %v", err)
	}
}

// The phase gate: a complete mocked backup session.
func TestBackupSessionFlow(t *testing.T) {
	m := pbsmock.New(t)
	s := start(t, clientFor(t, m, nil))
	ctx := context.Background()
	enc := pbs.NewBlobEncoder()

	if _, err := s.DownloadPrevious(ctx, "root.pxar.didx"); !errors.Is(err, pbs.ErrNoPrevious) {
		t.Fatalf("previous on first backup: %v", err)
	}

	wid, err := s.CreateDynamicIndex(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatal(err)
	}

	chunks := [][]byte{
		bytes.Repeat([]byte("compressible content "), 20_000),
		randomBytes(300_000), // incompressible: must go uncompressed
		[]byte("tiny"),
	}
	var (
		digests []string
		offsets []uint64
		offset  uint64
		csum    = sha256.New()
	)
	for _, chunk := range chunks {
		digest := sha256.Sum256(chunk)
		if err := s.UploadDynamicChunk(ctx, enc, wid, digest, chunk); err != nil {
			t.Fatal(err)
		}
		digests = append(digests, hex.EncodeToString(digest[:]))
		offsets = append(offsets, offset)
		offset += uint64(len(chunk))
		binary.Write(csum, binary.LittleEndian, offset) // end offset
		csum.Write(digest[:])
	}
	if err := s.AppendDynamicIndex(ctx, wid, digests, offsets); err != nil {
		t.Fatal(err)
	}
	var csumArr [32]byte
	copy(csumArr[:], csum.Sum(nil))
	if err := s.CloseDynamicIndex(ctx, wid, csumArr, offset, uint64(len(chunks))); err != nil {
		t.Fatal(err)
	}

	if err := s.UploadBlob(ctx, enc, "extra.blob", []byte("blob payload"), true); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx); err != nil {
		t.Fatal(err)
	}

	m.Mu.Lock()
	defer m.Mu.Unlock()
	if !m.Finished {
		t.Error("finish not recorded")
	}
	for i, chunk := range chunks {
		if got := m.Chunks[digests[i]]; !bytes.Equal(got, chunk) {
			t.Errorf("chunk %d: stored %d bytes, want %d", i, len(got), len(chunk))
		}
	}
	idx := m.Indexes[wid]
	if idx == nil || !idx.Closed || idx.Size != offset || idx.ChunkCount != 3 ||
		idx.Csum != hex.EncodeToString(csumArr[:]) {
		t.Errorf("index state: %+v", idx)
	}
	if !bytes.Equal(m.Blobs["extra.blob"], []byte("blob payload")) {
		t.Errorf("blob payload: %q", m.Blobs["extra.blob"])
	}

	var manifest struct {
		BackupID   string `json:"backup-id"`
		BackupType string `json:"backup-type"`
		Files      []struct {
			Filename  string `json:"filename"`
			Size      uint64 `json:"size"`
			Csum      string `json:"csum"`
			CryptMode string `json:"crypt-mode"`
		} `json:"files"`
	}
	if err := json.Unmarshal(m.Blobs["index.json.blob"], &manifest); err != nil {
		t.Fatalf("manifest: %v (%q)", err, m.Blobs["index.json.blob"])
	}
	if manifest.BackupID != "testhost" || manifest.BackupType != "host" {
		t.Errorf("manifest identity: %+v", manifest)
	}
	byName := map[string]int{}
	for i, f := range manifest.Files {
		byName[f.Filename] = i
	}
	pxarEntry := manifest.Files[byName["root.pxar.didx"]]
	if pxarEntry.Size != offset || pxarEntry.Csum != hex.EncodeToString(csumArr[:]) || pxarEntry.CryptMode != "none" {
		t.Errorf("manifest pxar entry: %+v", pxarEntry)
	}
	blobIdx, ok := byName["extra.blob"]
	if !ok {
		t.Fatal("manifest misses blob entry")
	}
	// Blob manifest entries carry the ENCODED blob's size and csum (as the
	// reference client records them); the official restore path verifies
	// both against the stored file and rejects raw-size entries.
	encoded := m.BlobsEncoded["extra.blob"]
	encSum := sha256.Sum256(encoded)
	blobEntry := manifest.Files[blobIdx]
	if blobEntry.Size != uint64(len(encoded)) || blobEntry.Csum != hex.EncodeToString(encSum[:]) {
		t.Errorf("manifest blob entry %+v, want encoded size %d and csum %x",
			blobEntry, len(encoded), encSum)
	}

	// A finished session refuses further use.
	if err := s.Finish(ctx); err == nil {
		t.Error("double finish must fail")
	}
}

func TestStatusPropagation(t *testing.T) {
	m := pbsmock.New(t)
	m.Mu.Lock()
	m.FailPath["/dynamic_index"] = 400
	m.Mu.Unlock()

	s := start(t, clientFor(t, m, nil))
	defer s.Abort()
	_, err := s.CreateDynamicIndex(context.Background(), "root.pxar.didx")
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "mock failure") {
		t.Fatalf("err = %v, want status and body", err)
	}

	// The session connection survives an endpoint error.
	if _, err := s.CreateDynamicIndex(context.Background(), "root.pxar.didx"); err != nil {
		t.Fatalf("second create after 400: %v", err)
	}
}

func TestUpgradeRefused(t *testing.T) {
	m := pbsmock.New(t)
	m.Mu.Lock()
	m.FailUpgrade = 404
	m.Mu.Unlock()

	_, err := clientFor(t, m, nil).StartBackup(context.Background(), pbs.SnapshotRef{ID: "x"})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v", err)
	}
}

func TestConnectionDropFailsSession(t *testing.T) {
	m := pbsmock.New(t)
	s := start(t, clientFor(t, m, nil))
	defer s.Abort()

	if _, err := s.CreateDynamicIndex(context.Background(), "a.didx"); err != nil {
		t.Fatal(err)
	}
	m.DropSessions()
	time.Sleep(50 * time.Millisecond)

	// No transparent re-dial: the session must fail, not silently open a
	// second backup.
	if _, err := s.CreateDynamicIndex(context.Background(), "b.didx"); err == nil {
		t.Fatal("call after connection drop must fail")
	}
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.UpgradeReqs) != 1 {
		t.Fatalf("%d upgrade requests: the client re-dialed", len(m.UpgradeReqs))
	}
}

func TestPreviousIndex(t *testing.T) {
	m := pbsmock.New(t)
	d1, d2 := sha256.Sum256([]byte("one")), sha256.Sum256([]byte("two"))
	m.Mu.Lock()
	m.Previous["root.pxar.didx"] = pbsmock.MakeDidx(d1, d2)
	m.Mu.Unlock()

	s := start(t, clientFor(t, m, nil))
	defer s.Abort()
	raw, err := s.DownloadPrevious(context.Background(), "root.pxar.didx")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := pbs.ParseDynamicIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Digest != d1 || entries[1].Digest != d2 ||
		entries[0].EndOffset != 1<<20 || entries[1].EndOffset != 2<<20 {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestParseDynamicIndexValidation(t *testing.T) {
	if _, err := pbs.ParseDynamicIndex([]byte("short")); err == nil {
		t.Error("short index must fail")
	}
	bad := pbsmock.MakeDidx(sha256.Sum256([]byte("x")))
	bad[0] = 0xff
	if _, err := pbs.ParseDynamicIndex(bad); err == nil {
		t.Error("bad magic must fail")
	}
	trailing := append(pbsmock.MakeDidx(sha256.Sum256([]byte("x"))), 0x01)
	if _, err := pbs.ParseDynamicIndex(trailing); err == nil {
		t.Error("trailing bytes must fail")
	}
	empty, err := pbs.ParseDynamicIndex(pbsmock.MakeDidx())
	if err != nil || len(empty) != 0 {
		t.Errorf("empty index: %v, %d entries", err, len(empty))
	}
}

func TestBlobEncoder(t *testing.T) {
	enc := pbs.NewBlobEncoder()
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()

	compressible := bytes.Repeat([]byte("abcd"), 10_000)
	framed := enc.Encode(compressible, true)
	if !bytes.Equal(framed[:8], []byte{49, 185, 88, 66, 111, 182, 163, 127}) {
		t.Fatalf("compressible data: magic %x", framed[:8])
	}
	plain, err := dec.DecodeAll(framed[12:], nil)
	if err != nil || !bytes.Equal(plain, compressible) {
		t.Fatalf("zstd roundtrip: %v", err)
	}

	random := randomBytes(4096)
	framed = append([]byte(nil), enc.Encode(random, true)...)
	if !bytes.Equal(framed[:8], []byte{66, 171, 56, 7, 190, 131, 112, 161}) {
		t.Fatalf("incompressible data: magic %x", framed[:8])
	}
	if !bytes.Equal(framed[12:], random) {
		t.Fatal("uncompressed payload mangled")
	}

	uncompressed := enc.Encode(compressible, false)
	if !bytes.Equal(uncompressed[:8], []byte{66, 171, 56, 7, 190, 131, 112, 161}) {
		t.Fatalf("compress=false: magic %x", uncompressed[:8])
	}
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	rand.New(rand.NewSource(1)).Read(buf)
	return buf
}

// The three ways servers report "nothing to seed from" must all map to
// ErrNoPrevious — pmoxs3's plain 404 (covered elsewhere), the real server's
// "no valid previous backup" (no previous snapshot at all), and its "Unable
// to open dynamic index ... No such file or directory" (previous snapshot
// exists but lacks the archive — e.g. the first v2 backup on an id with v1
// history). Other 400s must stay errors.
func TestDownloadPreviousMissingVariants(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		msg        string
		noPrevious bool
	}{
		{"real-no-snapshot", 400, "no valid previous backup", true},
		{"real-missing-archive", 400,
			`Unable to open dynamic index "/srv/tests/ct/x/2026-08-22T22:28:30Z/root.mpxar.didx" - No such file or directory (os error 2)`, true},
		{"real-missing-fixed-archive", 400,
			`Unable to open fixed index "/srv/tests/vm/x/2026-08-22T22:28:30Z/drive.img.fidx" - No such file or directory (os error 2)`, true},
		{"genuine-error", 400, "parameter verification failed - 'archive-name': property is missing", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := pbsmock.New(t)
			m.Mu.Lock()
			m.PreviousMissingStatus, m.PreviousMissingMsg = tc.status, tc.msg
			m.Mu.Unlock()

			s := start(t, clientFor(t, m, nil))
			defer s.Abort()

			_, err := s.DownloadPrevious(context.Background(), "root.mpxar.didx")
			if tc.noPrevious {
				if !errors.Is(err, pbs.ErrNoPrevious) {
					t.Fatalf("err = %v, want ErrNoPrevious", err)
				}
			} else if err == nil || errors.Is(err, pbs.ErrNoPrevious) {
				t.Fatalf("err = %v, want a real error", err)
			}
		})
	}
}
