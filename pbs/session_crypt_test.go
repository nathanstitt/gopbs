package pbs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/osshield/gopbs/chunker"
	"github.com/osshield/gopbs/internal/pbsmock"
	"github.com/osshield/gopbs/pbs"
)

// expectedChunksCrypt mirrors expectedChunks with the keyed digest rule.
func expectedChunksCrypt(t *testing.T, cfg *pbs.CryptConfig, data []byte, avg uint64) ([]expectedChunk, [32]byte) {
	t.Helper()
	var out []expectedChunk
	csum := sha256.New()
	for c, err := range chunker.Split(bytes.NewReader(data), avg) {
		if err != nil {
			t.Fatal(err)
		}
		d, err := pbs.CryptDigest(cfg, c.Data)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, expectedChunk{hex.EncodeToString(d[:]), c.Offset, uint64(len(c.Data))})
		binary.Write(csum, binary.LittleEndian, c.Offset+uint64(len(c.Data)))
		csum.Write(d[:])
	}
	var sum [32]byte
	copy(sum[:], csum.Sum(nil))
	return out, sum
}

// verifyManifestSignature recomputes the stored manifest's signature and
// fingerprint from the key and compares.
func verifyManifestSignature(t *testing.T, raw []byte, cfg *pbs.CryptConfig) {
	t.Helper()
	var m pbs.BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest: %v (%q)", err, raw)
	}
	sig, ok := m.Signature.(string)
	if !ok || sig == "" {
		t.Fatalf("manifest signature missing: %v", m.Signature)
	}
	canon, err := pbs.CanonicalManifestJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	want, err := pbs.CryptSignature(cfg, canon)
	if err != nil {
		t.Fatal(err)
	}
	if sig != hex.EncodeToString(want[:]) {
		t.Fatalf("manifest signature %s does not verify (want %x)", sig, want)
	}
	fp, err := pbs.CryptFingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Unprotected["key-fingerprint"]; got != fp {
		t.Fatalf("key-fingerprint %v, want %s", got, fp)
	}
}

func TestBackupSessionEncrypted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	key := testKey(t)
	cryptCfg := &pbs.CryptConfig{Mode: pbs.CryptModeEncrypt, Key: key, MasterPublicKey: pubPEM}

	m := pbsmock.New(t)
	m.SetCryptKey(key)
	s := start(t, clientFor(t, m, func(c *pbs.Config) { c.Crypt = cryptCfg }))
	ctx := context.Background()
	enc := pbs.NewBlobEncoder()

	wid, err := s.CreateDynamicIndex(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatal(err)
	}

	chunks := [][]byte{
		bytes.Repeat([]byte("compressible content "), 20_000),
		randomBytes(300_000),
	}
	var (
		digests []string
		offsets []uint64
		offset  uint64
		csum    = sha256.New()
	)
	for _, chunk := range chunks {
		digest := s.ChunkDigest(chunk)
		if plain := sha256.Sum256(chunk); digest == plain {
			t.Fatal("ChunkDigest returned the plain digest in encrypt mode")
		}
		if err := s.UploadDynamicChunk(ctx, enc, wid, digest, chunk); err != nil {
			t.Fatal(err)
		}
		digests = append(digests, hex.EncodeToString(digest[:]))
		offsets = append(offsets, offset)
		offset += uint64(len(chunk))
		binary.Write(csum, binary.LittleEndian, offset)
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

	// The mock decrypted each chunk with its own key, so a stored match
	// proves real encrypted framing (its digest check proved the keyed rule).
	for i, chunk := range chunks {
		if got := m.Chunks[digests[i]]; !bytes.Equal(got, chunk) {
			t.Errorf("chunk %d: stored %d bytes, want %d", i, len(got), len(chunk))
		}
	}

	// The blob went over the wire under an encrypted magic.
	if encoded := m.BlobsEncoded["extra.blob"]; len(encoded) == 0 || (encoded[0] != 123 && encoded[0] != 230) {
		t.Errorf("extra.blob not framed encrypted: % x", encoded[:8])
	}
	// The manifest is stored plain; the wrapped key blob is a plain frame
	// holding the RSA ciphertext.
	if encoded := m.BlobsEncoded["index.json.blob"]; len(encoded) == 0 || encoded[0] != 66 {
		t.Errorf("index.json.blob not framed plain: % x", encoded[:8])
	}
	if encoded := m.BlobsEncoded["rsa-encrypted.key.blob"]; len(encoded) == 0 || encoded[0] != 66 {
		t.Errorf("rsa-encrypted.key.blob not framed plain: % x", encoded[:8])
	}

	// The wrapped key decrypts with the master key back to our session key.
	//lint:ignore SA1019 the wrap format is PKCS#1 v1.5 for proxmox compatibility
	doc, err := rsa.DecryptPKCS1v15(nil, rsaKey, m.Blobs["rsa-encrypted.key.blob"])
	if err != nil {
		t.Fatalf("master-key decrypt: %v", err)
	}
	var wrapped struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(doc, &wrapped); err != nil {
		t.Fatal(err)
	}
	rawKey, err := base64.StdEncoding.DecodeString(wrapped.Data)
	if err != nil || !bytes.Equal(rawKey, key[:]) {
		t.Fatalf("wrapped key mismatch (err %v)", err)
	}

	// Manifest labels and signature.
	var manifest struct {
		Files []struct {
			Filename  string `json:"filename"`
			CryptMode string `json:"crypt-mode"`
		} `json:"files"`
	}
	if err := json.Unmarshal(m.Blobs["index.json.blob"], &manifest); err != nil {
		t.Fatal(err)
	}
	wantModes := map[string]string{
		"root.pxar.didx":         "encrypt",
		"extra.blob":             "encrypt",
		"rsa-encrypted.key.blob": "encrypt",
		"index.json.blob":        "none",
	}
	seen := map[string]bool{}
	for _, f := range manifest.Files {
		want, ok := wantModes[f.Filename]
		if !ok {
			t.Errorf("unexpected manifest entry %q", f.Filename)
			continue
		}
		seen[f.Filename] = true
		if f.CryptMode != want {
			t.Errorf("%s crypt-mode %q, want %q", f.Filename, f.CryptMode, want)
		}
	}
	for name := range wantModes {
		if name != "index.json.blob" && !seen[name] {
			t.Errorf("manifest misses %q", name)
		}
	}
	verifyManifestSignature(t, m.Blobs["index.json.blob"], cryptCfg)
}

func TestBackupSessionSignOnly(t *testing.T) {
	key := testKey(t)
	cryptCfg := &pbs.CryptConfig{Mode: pbs.CryptModeSignOnly, Key: key}

	// Deliberately no setCryptKey: sign-only data is plain, so the mock must
	// accept everything without a key.
	m := pbsmock.New(t)
	s := start(t, clientFor(t, m, func(c *pbs.Config) { c.Crypt = cryptCfg }))
	ctx := context.Background()
	enc := pbs.NewBlobEncoder()

	wid, err := s.CreateDynamicIndex(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatal(err)
	}
	chunk := []byte("sign-only payload")
	digest := s.ChunkDigest(chunk)
	if digest != sha256.Sum256(chunk) {
		t.Fatal("sign-only ChunkDigest is not the plain digest")
	}
	if err := s.UploadDynamicChunk(ctx, enc, wid, digest, chunk); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendDynamicIndex(ctx, wid, []string{hex.EncodeToString(digest[:])}, []uint64{0}); err != nil {
		t.Fatal(err)
	}
	csum := sha256.New()
	binary.Write(csum, binary.LittleEndian, uint64(len(chunk)))
	csum.Write(digest[:])
	var csumArr [32]byte
	copy(csumArr[:], csum.Sum(nil))
	if err := s.CloseDynamicIndex(ctx, wid, csumArr, uint64(len(chunk)), 1); err != nil {
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
	if _, ok := m.Blobs["rsa-encrypted.key.blob"]; ok {
		t.Error("sign-only session uploaded a wrapped key")
	}
	var manifest struct {
		Files []struct {
			Filename  string `json:"filename"`
			CryptMode string `json:"crypt-mode"`
		} `json:"files"`
	}
	if err := json.Unmarshal(m.Blobs["index.json.blob"], &manifest); err != nil {
		t.Fatal(err)
	}
	for _, f := range manifest.Files {
		want := "sign-only"
		if f.Filename == "index.json.blob" {
			want = "none"
		}
		if f.CryptMode != want {
			t.Errorf("%s crypt-mode %q, want %q", f.Filename, f.CryptMode, want)
		}
	}
	verifyManifestSignature(t, m.Blobs["index.json.blob"], cryptCfg)
}

// TestUploadPipelineEncrypted runs the full worker pipeline in encrypt mode:
// keyed digests must drive intra-stream dedup and the index checksum.
func TestUploadPipelineEncrypted(t *testing.T) {
	key := testKey(t)
	cryptCfg := &pbs.CryptConfig{Key: key}

	m := pbsmock.New(t)
	m.SetCryptKey(key)
	data := pipelineData(t)
	const avg = 64 << 10
	expected, wantCsum := expectedChunksCrypt(t, cryptCfg, data, avg)

	c := clientFor(t, m, func(cfg *pbs.Config) {
		cfg.Workers = 8
		cfg.ChunkSizeAvg = avg
		cfg.Crypt = cryptCfg
	})
	s := start(t, c)
	defer s.Abort()

	stats, err := s.UploadPXARv1(context.Background(), "root.pxar", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if stats.ReusedChunks == 0 {
		t.Error("repeated region produced no dedup under encryption")
	}

	m.Mu.Lock()
	defer m.Mu.Unlock()
	var idx *pbsmock.Index
	for _, i := range m.Indexes {
		if i.Name == "root.pxar.didx" {
			idx = i
		}
	}
	if idx == nil || !idx.Closed {
		t.Fatalf("index missing or not closed: %+v", idx)
	}
	if idx.Csum != hex.EncodeToString(wantCsum[:]) {
		t.Errorf("index csum %s, want %s", idx.Csum, hex.EncodeToString(wantCsum[:]))
	}
	uniq := make(map[string]bool)
	for _, e := range expected {
		uniq[e.digest] = true
	}
	if len(m.Chunks) != len(uniq) {
		t.Errorf("server stores %d chunks, want %d unique", len(m.Chunks), len(uniq))
	}
}

// A second encrypted backup of identical content deduplicates fully against
// the previous index's keyed digests.
func TestUploadPipelineEncryptedPreviousDedup(t *testing.T) {
	key := testKey(t)
	cryptCfg := &pbs.CryptConfig{Key: key}

	m := pbsmock.New(t)
	m.SetCryptKey(key)
	data := pipelineData(t)
	const avg = 64 << 10
	expected, _ := expectedChunksCrypt(t, cryptCfg, data, avg)

	var digests [][32]byte
	for _, e := range expected {
		raw, err := hex.DecodeString(e.digest)
		if err != nil {
			t.Fatal(err)
		}
		var d [32]byte
		copy(d[:], raw)
		digests = append(digests, d)
	}
	m.Mu.Lock()
	m.Previous["root.pxar.didx"] = pbsmock.MakeDidx(digests...)
	m.Mu.Unlock()

	c := clientFor(t, m, func(cfg *pbs.Config) {
		cfg.Workers = 4
		cfg.ChunkSizeAvg = avg
		cfg.Crypt = cryptCfg
	})
	s := start(t, c)
	defer s.Abort()

	stats, err := s.UploadPXARv1(context.Background(), "root.pxar.didx", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if stats.NewChunks != 0 || stats.ReusedChunks != stats.ChunkCount {
		t.Errorf("stats %+v: everything should deduplicate", stats)
	}
	m.Mu.Lock()
	defer m.Mu.Unlock()
	if len(m.Chunks) != 0 {
		t.Errorf("%d chunks uploaded despite full dedup", len(m.Chunks))
	}
}
