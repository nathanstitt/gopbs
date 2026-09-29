package pbs_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"github.com/osshield/gopbs/chunker"
	"github.com/osshield/gopbs/internal/pbsmock"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/reuse"
)

// didxFor builds a dynamic index with the real chunk sizes
func didxFor(chunks []reuse.Chunk) []byte {
	out := make([]byte, 4096, 4096+40*len(chunks))
	copy(out, []byte{28, 145, 78, 165, 25, 186, 179, 205})
	offset := uint64(0)
	for _, c := range chunks {
		offset += c.Size
		out = binary.LittleEndian.AppendUint64(out, offset)
		out = append(out, c.Digest[:]...)
	}
	return out
}

func seededBytes(n int, seed int64) []byte {
	buf := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(buf)
	return buf
}

// TestUploadPXARv2Reuse: a framed payload stream injects previous chunks
// between data segments; the index must carry them at the right offsets
// without uploading them, and data segments must be cut at the injections.
func TestUploadPXARv2Reuse(t *testing.T) {
	const avg = 64 << 10
	prevPayload := seededBytes(1<<20, 1)
	var prevChunks []reuse.Chunk
	for c, err := range chunker.Split(bytes.NewReader(prevPayload), avg) {
		if err != nil {
			t.Fatal(err)
		}
		prevChunks = append(prevChunks, reuse.Chunk{Digest: sha256.Sum256(c.Data), Size: uint64(len(c.Data))})
	}
	if len(prevChunks) < 4 {
		t.Fatalf("previous payload has only %d chunks", len(prevChunks))
	}
	injected := prevChunks[1:3]

	m := pbsmock.New(t)
	m.Mu.Lock()
	m.Previous["root.ppxar.didx"] = didxFor(prevChunks)
	m.Mu.Unlock()

	segA := seededBytes(300<<10, 2)
	segB := seededBytes(200<<10, 3)
	var framed bytes.Buffer
	fw := reuse.NewWriter(&framed)
	fw.Write(segA)
	fw.Inject(injected)
	fw.Write(segB)

	expA, _ := expectedChunks(t, segA, avg)
	expB, _ := expectedChunks(t, segB, avg)
	metaData := []byte("metadata stream")

	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.Workers = 4; cfg.ChunkSizeAvg = avg })
	s := start(t, c)
	defer s.Abort()
	_, payloadStats, err := s.UploadPXARv2(context.Background(), "root.pxar", bytes.NewReader(metaData), bytes.NewReader(framed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	wantSize := uint64(len(segA) + len(segB))
	for _, ch := range injected {
		wantSize += ch.Size
	}
	if payloadStats.Size != wantSize {
		t.Errorf("payload size %d, want %d", payloadStats.Size, wantSize)
	}
	if payloadStats.ReusedChunks != 2 || payloadStats.NewChunks != uint64(len(expA)+len(expB)) {
		t.Errorf("stats %+v, want 2 reused and %d new", payloadStats, len(expA)+len(expB))
	}
	if len(payloadStats.Entries) != int(payloadStats.ChunkCount) || payloadStats.Entries[len(payloadStats.Entries)-1].EndOffset != wantSize {
		t.Errorf("entries %d (chunks %d), last end %d", len(payloadStats.Entries), payloadStats.ChunkCount, payloadStats.Entries[len(payloadStats.Entries)-1].EndOffset)
	}

	m.Mu.Lock()
	defer m.Mu.Unlock()
	var idx *pbsmock.Index
	for _, i := range m.Indexes {
		if i.Name == "root.ppxar.didx" {
			idx = i
		}
	}
	if idx == nil || !idx.Closed {
		t.Fatal("payload index missing or not closed")
	}
	// Order: segA's chunks, the two injected chunks, segB's chunks; offsets contiguous
	var want []string
	for _, e := range expA {
		want = append(want, e.digest)
	}
	for _, ch := range injected {
		want = append(want, hex.EncodeToString(ch.Digest[:]))
	}
	for _, e := range expB {
		want = append(want, e.digest)
	}
	if strings.Join(idx.Digests, ",") != strings.Join(want, ",") {
		t.Fatalf("index digests\n got %v\nwant %v", idx.Digests, want)
	}
	offset := uint64(0)
	for i, o := range idx.Offsets {
		if o != offset {
			t.Fatalf("entry %d at offset %d, want %d", i, o, offset)
		}
		offset = payloadStats.Entries[i].EndOffset
	}
	for _, ch := range injected {
		if _, uploaded := m.Chunks[hex.EncodeToString(ch.Digest[:])]; uploaded {
			t.Error("an injected chunk was uploaded")
		}
	}
}

func TestUploadPXARv2ReuseUnknownChunk(t *testing.T) {
	m := pbsmock.New(t)
	var framed bytes.Buffer
	fw := reuse.NewWriter(&framed)
	fw.Write(seededBytes(10<<10, 4))
	fw.Inject([]reuse.Chunk{{Digest: sha256.Sum256([]byte("never uploaded")), Size: 1234}})
	fw.Write(seededBytes(10<<10, 5))

	c := clientFor(t, m, func(cfg *pbs.Config) { cfg.ChunkSizeAvg = 64 << 10 })
	s := start(t, c)
	defer s.Abort()
	_, _, err := s.UploadPXARv2(context.Background(), "root.pxar", bytes.NewReader([]byte("meta")), bytes.NewReader(framed.Bytes()))
	if err == nil || !strings.Contains(err.Error(), "not known to the session") {
		t.Fatalf("expected an unknown-chunk error, got %v", err)
	}
}
