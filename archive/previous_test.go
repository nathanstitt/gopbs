//go:build linux

package archive_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/chunker"
	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/reuse"
)

// chunkAvg keeps chunks small so a run of a few files spans many chunks and
// boundary padding stays well under the threshold
const chunkAvg = 4096

func writeRandom(t *testing.T, path string, n int, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	buf := make([]byte, n)
	rng.Read(buf)
	if err := os.WriteFile(path, buf, 0o640); err != nil {
		t.Fatal(err)
	}
}

// reuseTree: a directory with several sizeable files, a nested directory, a
// symlink and a hardlink pair
func reuseTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"a.bin", "b.bin", "c.bin", "sub/d.bin", "sub/e.bin", "sub/f.bin"} {
		writeRandom(t, filepath.Join(root, name), 200<<10, int64(i+1))
	}
	if err := os.WriteFile(filepath.Join(root, "small.txt"), []byte("tiny"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.bin", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "b.bin"), filepath.Join(root, "sub", "b-hard.bin")); err != nil {
		t.Fatal(err)
	}
	// Stable mtimes so the second scan sees identical metadata
	stamp := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode()&os.ModeSymlink == 0 {
			_ = os.Chtimes(p, stamp, stamp)
		}
		return nil
	})
	return root
}

// payloadChunks chunks a payload stream like the uploader does and returns
// the index entries plus the chunk contents by digest
func payloadChunks(t *testing.T, payload []byte) ([]archive.PayloadChunk, map[[32]byte][]byte) {
	t.Helper()
	var entries []archive.PayloadChunk
	data := map[[32]byte][]byte{}
	for c, err := range chunker.Split(bytes.NewReader(payload), chunkAvg) {
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(c.Data)
		entries = append(entries, archive.PayloadChunk{EndOffset: c.Offset + uint64(len(c.Data)), Digest: d})
		data[d] = c.Data
	}
	return entries, data
}

// rebuildPayload turns a framed payload stream back into the ppxar bytes the
// server would hold: data frames verbatim, injected chunks from the previous
// payload's chunk contents
func rebuildPayload(t *testing.T, framed []byte, prevChunks map[[32]byte][]byte) (out []byte, injected int) {
	t.Helper()
	r, _, err := reuse.NewReader(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("payload stream is not framed: %v", err)
	}
	for {
		kind, data, chunks, err := r.Next()
		if err == io.EOF {
			return out, injected
		}
		if err != nil {
			t.Fatal(err)
		}
		switch kind {
		case reuse.KindData:
			out = append(out, data...)
		case reuse.KindInject:
			for _, c := range chunks {
				d, ok := prevChunks[c.Digest]
				if !ok || uint64(len(d)) != c.Size {
					t.Fatalf("injected chunk %x unknown or size %d != %d", c.Digest[:4], len(d), c.Size)
				}
				out = append(out, d...)
				injected++
			}
		}
	}
}

// verifyArchive decodes the metadata stream and checks every file's payload
// record against the file on disk; refs need not be contiguous (gaps are the
// padding of reused chunks)
func verifyArchive(t *testing.T, root string, meta, payload []byte) map[string]uint64 {
	t.Helper()
	offsets := map[string]uint64{}
	if binary.LittleEndian.Uint64(payload) != pxar.PayloadStartMarker {
		t.Fatal("payload start marker missing")
	}
	tail := len(payload) - pxar.MarkerSize
	if binary.LittleEndian.Uint64(payload[tail:]) != pxar.PayloadTailMarker {
		t.Fatal("payload tail marker missing")
	}
	version, err := pxar.DecodeMetadata(bytes.NewReader(meta), func(f pxar.MetaFile) error {
		offsets[f.Path] = f.PayloadOffset
		if f.PayloadOffset+pxar.HeaderSize+f.Size > uint64(tail) {
			t.Fatalf("%s: ref %d+%d beyond payload (%d)", f.Path, f.PayloadOffset, f.Size, tail)
		}
		rec := payload[f.PayloadOffset:]
		if binary.LittleEndian.Uint64(rec) != pxar.TypePayload || binary.LittleEndian.Uint64(rec[8:]) != pxar.HeaderSize+f.Size {
			t.Fatalf("%s: ref does not address a payload record of %d bytes", f.Path, f.Size)
		}
		want, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rec[pxar.HeaderSize:pxar.HeaderSize+f.Size], want) {
			t.Fatalf("%s: archived content differs from disk", f.Path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("version %d", version)
	}
	return offsets
}

func TestDecodeMetadataMatchesGeneration(t *testing.T) {
	root := reuseTree(t)
	a, err := archive.New(archive.Options{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AddDirectory(root); err != nil {
		t.Fatal(err)
	}
	meta, payload := generateV2(t, a)
	offsets := verifyArchive(t, root, meta, payload)
	// 7 regular files (the hardlink is encoded as a link, not a file)
	if len(offsets) != 7 {
		t.Fatalf("decoded %d files: %v", len(offsets), offsets)
	}
	for _, p := range []string{"a.bin", "sub/d.bin", "small.txt"} {
		if _, ok := offsets[p]; !ok {
			t.Errorf("file %s not decoded", p)
		}
	}
	// Refs of a plain generation are contiguous from the start marker
	if offsets["a.bin"] != pxar.MarkerSize {
		t.Errorf("first ref at %d", offsets["a.bin"])
	}
}

func TestGenerateV2MetadataReuse(t *testing.T) {
	root := reuseTree(t)
	gen := func(prev *archive.Previous, workers int) (*archive.Archive, []byte, []byte) {
		a, err := archive.New(archive.Options{Workers: workers, Previous: prev})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.AddDirectory(root); err != nil {
			t.Fatal(err)
		}
		meta, payload := generateV2(t, a)
		return a, meta, payload
	}

	// Snapshot 1: everything read
	_, meta1, payload1 := gen(nil, 1)
	entries, prevData := payloadChunks(t, payload1)
	prev, err := archive.LoadPrevious(bytes.NewReader(meta1), entries)
	if err != nil {
		t.Fatal(err)
	}
	if prev.Files() != 7 {
		t.Fatalf("previous knows %d files", prev.Files())
	}

	// Changes: c.bin rewritten (new mtime), sub/e.bin chmod, a new file, small.txt removed
	writeRandom(t, filepath.Join(root, "c.bin"), 200<<10, 99)
	if err := os.Chmod(filepath.Join(root, "sub", "e.bin"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRandom(t, filepath.Join(root, "sub", "new.bin"), 50<<10, 77)
	if err := os.Remove(filepath.Join(root, "small.txt")); err != nil {
		t.Fatal(err)
	}

	for _, workers := range []int{1, 4} {
		a, meta2, framed := gen(prev, workers)
		stats := a.ReuseStats()
		payload2, injected := rebuildPayload(t, framed, prevData)
		offsets := verifyArchive(t, root, meta2, payload2)
		if len(offsets) != 7 {
			t.Fatalf("workers=%d: decoded %d files", workers, len(offsets))
		}
		if stats.Files != 7 || stats.ReusedFiles == 0 || injected == 0 {
			t.Fatalf("workers=%d: no reuse happened: %+v (injected %d)", workers, stats, injected)
		}
		// a.bin, b.bin (before the change) and sub/d.bin, sub/f.bin are unchanged;
		// c.bin, sub/e.bin and sub/new.bin must be read
		if stats.ReusedFiles > 4 {
			t.Fatalf("workers=%d: %d files reused, at most 4 are unchanged", workers, stats.ReusedFiles)
		}
		if stats.ReusedFiles < 2 {
			t.Fatalf("workers=%d: only %d files reused: %+v", workers, stats.ReusedFiles, stats)
		}
		if stats.InjectedBytes < stats.ReusedBytes {
			t.Fatalf("workers=%d: injected %d < reused %d", workers, stats.InjectedBytes, stats.ReusedBytes)
		}
		t.Logf("workers=%d: %+v", workers, stats)
	}

	// Without a previous archive the stream is plain (no magic)
	_, _, plain := gen(nil, 1)
	if bytes.HasPrefix(plain, []byte(reuse.Magic)) {
		t.Fatal("plain generation must not be framed")
	}
}

func TestReusePaddingThreshold(t *testing.T) {
	root := t.TempDir()
	// One tiny file between two big ones: reusing its single chunk would drag in
	// mostly padding, so it is read; the big ones are reused
	writeRandom(t, filepath.Join(root, "a.bin"), 300<<10, 1)
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("small"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeRandom(t, filepath.Join(root, "c.bin"), 300<<10, 2)
	stamp := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, n := range []string{"a.bin", "b.txt", "c.bin"} {
		_ = os.Chtimes(filepath.Join(root, n), stamp, stamp)
	}
	_ = os.Chtimes(root, stamp, stamp)

	a1, _ := archive.New(archive.Options{Workers: 1})
	_ = a1.AddDirectory(root)
	meta1, payload1 := generateV2(t, a1)
	entries, prevData := payloadChunks(t, payload1)
	prev, err := archive.LoadPrevious(bytes.NewReader(meta1), entries)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing changed: one run covering everything, no padding at all
	a2, _ := archive.New(archive.Options{Workers: 1, Previous: prev})
	_ = a2.AddDirectory(root)
	meta2, framed := generateV2(t, a2)
	payload2, _ := rebuildPayload(t, framed, prevData)
	verifyArchive(t, root, meta2, payload2)
	// The injected span is the whole previous stream: three payload records plus
	// the previous start and tail markers, which ride along inside the first
	// and last chunk as padding
	if st := a2.ReuseStats(); st.ReusedFiles != 3 || st.RejectedRuns != 0 || st.InjectedBytes != st.ReusedBytes+3*pxar.HeaderSize+2*pxar.MarkerSize {
		t.Fatalf("unchanged tree: %+v", st)
	}
	if len(payload2) != len(payload1)+2*pxar.MarkerSize || !bytes.Equal(payload2[pxar.MarkerSize:len(payload2)-pxar.MarkerSize], payload1) {
		t.Fatal("an unchanged tree must rebuild the previous payload stream wrapped in new markers")
	}

	// A strict threshold rejects runs whose boundary chunks carry any padding:
	// change a.bin so b.txt+c.bin form the run, starting mid-chunk
	writeRandom(t, filepath.Join(root, "a.bin"), 300<<10, 5)
	a3, _ := archive.New(archive.Options{Workers: 1, Previous: prev, PaddingThreshold: 1e-9})
	_ = a3.AddDirectory(root)
	meta3, framed3 := generateV2(t, a3)
	payload3, _ := rebuildPayload(t, framed3, prevData)
	verifyArchive(t, root, meta3, payload3)
	if st := a3.ReuseStats(); st.ReusedFiles != 0 || st.RejectedRuns != 1 {
		t.Fatalf("strict threshold: %+v", st)
	}
	// The default threshold accepts the same run (tens of bytes of padding on
	// hundreds of KiB)
	a4, _ := archive.New(archive.Options{Workers: 1, Previous: prev})
	_ = a4.AddDirectory(root)
	meta4, framed4 := generateV2(t, a4)
	payload4, _ := rebuildPayload(t, framed4, prevData)
	verifyArchive(t, root, meta4, payload4)
	if st := a4.ReuseStats(); st.ReusedFiles != 2 {
		t.Fatalf("default threshold: %+v", st)
	}
}
