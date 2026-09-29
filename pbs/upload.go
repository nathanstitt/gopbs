package pbs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/osshield/gopbs/chunker"
	"github.com/osshield/gopbs/reuse"
)

// UploadStats summarizes one index upload.
type UploadStats struct {
	Size         uint64 // total bytes indexed
	ChunkCount   uint64
	NewChunks    uint64 // uploaded to the server
	NewBytes     uint64 // plain size of the chunks uploaded to the server
	ReusedChunks uint64 // deduplicated (previous snapshot or repeats in this stream)
	// Entries is the index as closed on the server (end offset + digest per
	// chunk); callers keeping a local copy of a v2 metadata stream for change
	// detection store it to validate the copy against the next snapshot's
	// previous index.
	Entries []IndexEntry
}

// UploadPXARv1 streams a pxar v1 archive into a dynamic index: the stream is
// content-defined-chunked, chunks are hashed, deduplicated, compressed and
// uploaded by Config.Workers concurrent workers, and the index is appended
// strictly in stream order and closed with its checksum. Deduplication is
// seeded from the previous snapshot's index automatically and shared across
// all uploads of the session. name may be "root.pxar" or "root.pxar.didx".
func (s *BackupSession) UploadPXARv1(ctx context.Context, name string, r io.Reader) (UploadStats, error) {
	if !strings.HasSuffix(name, ".didx") {
		name += ".didx"
	}
	return s.uploadIndexStream(ctx, name, r)
}

// UploadStream is UploadPXARv1 for any byte stream. The official client
// restores such an index only to stdout:
// "proxmox-backup-client restore <snapshot> NAME.didx -".
func (s *BackupSession) UploadStream(ctx context.Context, name string, r io.Reader) (UploadStats, error) {
	if !strings.HasSuffix(name, ".didx") {
		name += ".didx"
	}
	return s.uploadIndexStream(ctx, name, r)
}

// UploadCatalog streams a .pcat1 catalog into the snapshot's
// "catalog.pcat1.didx" index, making it browsable in the PBS UI.
func (s *BackupSession) UploadCatalog(ctx context.Context, r io.Reader) (UploadStats, error) {
	return s.uploadIndexStream(ctx, "catalog.pcat1.didx", r)
}

// SplitIndexNames derives the dynamic index names of a v2 split archive from
// an archive name in any customary spelling ("root", "root.pxar",
// "root.pxar.didx", or one of the split names): "<base>.mpxar.didx" for the
// metadata stream and "<base>.ppxar.didx" for the payload stream. An empty
// name maps to base "backup".
func SplitIndexNames(name string) (meta, payload string) {
	base := strings.TrimSuffix(name, ".didx")
	for _, suffix := range []string{".pxar", ".mpxar", ".ppxar"} {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	if base == "" {
		base = "backup"
	}
	return base + ".mpxar.didx", base + ".ppxar.didx"
}

// UploadPXARv2 streams a split v2 archive — metadata stream and payload
// stream — into its two dynamic indexes ("<base>.mpxar.didx" and
// "<base>.ppxar.didx"; see SplitIndexNames). The two streams are uploaded
// concurrently: generators couple the streams (metadata emission can await
// payload dispatch), so consuming them sequentially could deadlock.
// Deduplication is shared with all other uploads of the session.
//
// A payload stream produced with metadata change detection is framed (see
// package reuse): its injected chunks — previous-snapshot chunks the
// generator did not re-read — are appended to the index without upload.
// They must be known to the session, which DownloadPrevious of the payload
// index guarantees when the previous snapshot is the one the generator
// compared against.
func (s *BackupSession) UploadPXARv2(ctx context.Context, name string, meta, payload io.Reader) (metaStats, payloadStats UploadStats, err error) {
	metaName, payloadName := SplitIndexNames(name)

	uctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg         sync.WaitGroup
		payloadErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		payloadStats, payloadErr = s.uploadIndexStream(uctx, payloadName, payload)
		if payloadErr != nil {
			cancel()
		}
	}()
	metaStats, err = s.uploadIndexStream(uctx, metaName, meta)
	if err != nil {
		cancel()
	}
	wg.Wait()
	// Whichever stream failed first canceled the other: report the root cause,
	// not the cancellation it provoked
	canceled := func(e error) bool {
		return errors.Is(e, context.Canceled) || strings.Contains(e.Error(), context.Canceled.Error())
	}
	switch {
	case err == nil:
		err = payloadErr
	case payloadErr != nil && canceled(err) && !canceled(payloadErr):
		err = payloadErr
	}
	return metaStats, payloadStats, err
}

type chunkJob struct {
	seq    int
	offset uint64
	data   []byte
	// known: an injected previous chunk, referenced by digest without data
	known  bool
	digest [32]byte
	size   uint64
}

type chunkDone struct {
	seq    int
	offset uint64
	size   uint64
	digest [32]byte
	reused bool
	err    error
}

func (s *BackupSession) uploadIndexStream(ctx context.Context, name string, r io.Reader) (UploadStats, error) {
	var stats UploadStats

	// Seed deduplication from the previous snapshot; its absence is the
	// normal first-backup case. (DownloadPrevious registers the digests
	// with the session's known set as a side effect.)
	if _, err := s.DownloadPrevious(ctx, name); err != nil && !errors.Is(err, ErrNoPrevious) {
		return stats, err
	}

	wid, err := s.CreateDynamicIndex(ctx, name)
	if err != nil {
		return stats, err
	}

	workers := s.client.cfg.Workers
	if workers == 0 {
		workers = 4
	}

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan chunkJob, workers)
	dones := make(chan chunkDone, workers*2)
	prodErr := make(chan error, 1)

	// Producer: cut content-defined chunks in stream order; a framed stream
	// additionally yields the chunks to inject at their positions.
	go func() {
		defer close(jobs)
		emit := func(j chunkJob) bool {
			select {
			case jobs <- j:
				return true
			case <-gctx.Done():
				return false
			}
		}
		fr, prefix, err := reuse.NewReader(r)
		if err != nil && !errors.Is(err, reuse.ErrNotFramed) {
			prodErr <- err
			return
		}
		if fr == nil {
			seq := 0
			for c, err := range chunker.Split(io.MultiReader(bytes.NewReader(prefix), r), s.client.cfg.ChunkSizeAvg) {
				if err != nil {
					prodErr <- err
					return
				}
				if !emit(chunkJob{seq: seq, offset: c.Offset, data: c.Data}) {
					prodErr <- gctx.Err()
					return
				}
				seq++
			}
			prodErr <- nil
			return
		}
		if err := produceFramed(fr, s.client.cfg.ChunkSizeAvg, emit); err != nil {
			if gctx.Err() != nil {
				err = gctx.Err()
			}
			prodErr <- err
			return
		}
		prodErr <- nil
	}()

	// Workers: hash, dedup (singleflight across the session), compress,
	// upload. Every job produces exactly one done, errors included.
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enc := NewBlobEncoder()
			for j := range jobs {
				d := chunkDone{seq: j.seq, offset: j.offset, size: uint64(len(j.data))}
				if j.known {
					d.size, d.digest = j.size, j.digest
				} else {
					d.digest = s.ChunkDigest(j.data)
				}

				st, winner := s.known.claim(d.digest)
				switch {
				case winner && j.known:
					// An injected chunk nobody uploaded and the previous index did
					// not register: the generator compared against a snapshot that
					// is not the server's previous one
					err := fmt.Errorf("reused chunk %x is not known to the session (previous snapshot mismatch)", d.digest[:8])
					st.complete(err)
					d.err = err
				case winner:
					err := s.UploadDynamicChunk(gctx, enc, wid, d.digest, j.data)
					st.complete(err)
					d.err = err
				default:
					select {
					case <-st.wait():
						d.err = st.err
						d.reused = d.err == nil
					case <-gctx.Done():
						d.err = gctx.Err()
					}
				}
				dones <- d
			}
		}()
	}
	go func() {
		wg.Wait()
		close(dones)
	}()

	// Collector: reassemble completions into strict stream order — the
	// server requires contiguous ascending appends — maintaining the index
	// checksum (sha256 over LE end-offset ‖ digest per chunk).
	var (
		firstErr error
		pending  = make(map[int]chunkDone)
		next     = 0
		csum     = sha256.New()
		digests  []string
		offsets  []uint64
	)
	flush := func() error {
		if len(digests) == 0 {
			return nil
		}
		if err := s.AppendDynamicIndex(ctx, wid, digests, offsets); err != nil {
			return err
		}
		digests, offsets = digests[:0], offsets[:0]
		return nil
	}
	for d := range dones {
		if firstErr != nil {
			continue // drain
		}
		if d.err != nil {
			firstErr = d.err
			cancel()
			continue
		}
		pending[d.seq] = d
		for {
			cur, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++

			stats.Size = cur.offset + cur.size
			stats.ChunkCount++
			if cur.reused {
				stats.ReusedChunks++
			} else {
				stats.NewChunks++
				stats.NewBytes += cur.size
			}
			binary.Write(csum, binary.LittleEndian, cur.offset+cur.size)
			csum.Write(cur.digest[:])
			stats.Entries = append(stats.Entries, IndexEntry{EndOffset: cur.offset + cur.size, Digest: cur.digest})
			digests = append(digests, hex.EncodeToString(cur.digest[:]))
			offsets = append(offsets, cur.offset)
			if cb := s.client.cfg.OnUploadProgress; cb != nil {
				cb(name, stats, false)
			}
			if len(digests) == 128 {
				if firstErr = flush(); firstErr != nil {
					cancel()
					break
				}
			}
		}
	}
	if err := <-prodErr; err != nil && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return stats, fmt.Errorf("pbs: uploading %s: %w", name, firstErr)
	}
	if len(pending) != 0 {
		return stats, fmt.Errorf("pbs: uploading %s: %d chunks unaccounted for", name, len(pending))
	}
	if err := flush(); err != nil {
		return stats, err
	}

	var csumArr [32]byte
	copy(csumArr[:], csum.Sum(nil))
	if err := s.CloseDynamicIndex(ctx, wid, csumArr, stats.Size, stats.ChunkCount); err != nil {
		return stats, err
	}
	if cb := s.client.cfg.OnUploadProgress; cb != nil {
		cb(name, stats, true)
	}
	return stats, nil
}

// produceFramed chunks the data frames of a framed payload stream and turns
// injection frames into known-chunk jobs: an injection forces a chunk
// boundary (the bytes read so far form a chunk, however short) so the
// previous chunks slot in at exactly their position.
func produceFramed(fr *reuse.Reader, avg uint64, emit func(chunkJob) bool) error {
	c, err := chunker.New(avg)
	if err != nil {
		return err
	}
	var (
		current []byte
		offset  uint64
		seq     int
	)
	cut := func() bool {
		if len(current) == 0 {
			return true
		}
		if !emit(chunkJob{seq: seq, offset: offset, data: current}) {
			return false
		}
		seq++
		offset += uint64(len(current))
		current = nil
		return true
	}
	for {
		kind, data, chunks, err := fr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch kind {
		case reuse.KindData:
			seg := data
			for len(seg) > 0 {
				pos := c.Scan(seg)
				if pos == 0 {
					current = append(current, seg...)
					break
				}
				current = append(current, seg[:pos]...)
				if !cut() {
					return errors.New("canceled")
				}
				seg = seg[pos:]
			}
		case reuse.KindInject:
			if !cut() {
				return errors.New("canceled")
			}
			c.Reset()
			for _, ch := range chunks {
				if ch.Size == 0 {
					return errors.New("reuse: injected chunk of size 0")
				}
				if !emit(chunkJob{seq: seq, offset: offset, known: true, digest: ch.Digest, size: ch.Size}) {
					return errors.New("canceled")
				}
				seq++
				offset += ch.Size
			}
		}
	}
	if !cut() {
		return errors.New("canceled")
	}
	return nil
}

// chunkSet is the session-wide known-chunk registry with singleflight
// semantics: the first claimant of a digest uploads it, concurrent claimants
// wait for that upload before referencing the digest in an index append.
type chunkSet struct {
	mu sync.Mutex
	m  map[[32]byte]*chunkState
}

type chunkState struct {
	done chan struct{}
	err  error
}

func newChunkSet() *chunkSet {
	return &chunkSet{m: make(map[[32]byte]*chunkState)}
}

// claim returns the digest's state and whether the caller is the winner
// responsible for uploading it (and calling complete).
func (cs *chunkSet) claim(digest [32]byte) (*chunkState, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if st, ok := cs.m[digest]; ok {
		return st, false
	}
	st := &chunkState{done: make(chan struct{})}
	cs.m[digest] = st
	return st, true
}

// seed marks a digest as already present on the server (previous snapshot).
func (cs *chunkSet) seed(digest [32]byte) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, ok := cs.m[digest]; !ok {
		st := &chunkState{done: make(chan struct{})}
		close(st.done)
		cs.m[digest] = st
	}
}

func (st *chunkState) wait() <-chan struct{} { return st.done }

func (st *chunkState) complete(err error) {
	st.err = err
	close(st.done)
}
