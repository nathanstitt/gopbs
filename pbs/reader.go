package pbs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
)

const readerProtocol = "proxmox-backup-reader-protocol-v1"

// ReaderSession reads one committed snapshot. Its methods are safe for
// concurrent use; Close must come last.
type ReaderSession struct {
	client *Client
	conn   net.Conn
	cc     *http2.ClientConn
	ref    SnapshotRef

	mu       sync.Mutex
	manifest *SnapshotManifest
}

// SnapshotManifest is a snapshot's decoded index.json.blob.
type SnapshotManifest struct {
	Ref   SnapshotRef
	Files []ManifestFile
}

func (m *SnapshotManifest) file(name string) (ManifestFile, bool) {
	for _, f := range m.Files {
		if f.Filename == name {
			return f, true
		}
	}
	return ManifestFile{}, false
}

// StartReader opens a reader session on one snapshot. ref.ID and ref.Time
// are required. Config.DialSession is not used: that dialer cannot tell
// which protocol to upgrade to.
func (c *Client) StartReader(ctx context.Context, ref SnapshotRef) (*ReaderSession, error) {
	if ref.ID == "" {
		return nil, fmt.Errorf("pbs: reader requires a backup id")
	}
	if ref.Time.IsZero() {
		return nil, fmt.Errorf("pbs: reader requires a backup time")
	}
	ref, err := ref.withDefaults()
	if err != nil {
		return nil, err
	}
	if c.cfg.Auth == nil || c.cfg.Datastore == "" || c.cfg.BaseURL == "" {
		return nil, fmt.Errorf("pbs: reader requires Config.BaseURL, Auth and Datastore")
	}

	query := url.Values{
		"backup-type": {ref.Type},
		"backup-id":   {ref.ID},
		"backup-time": {strconv.FormatInt(ref.Time.Unix(), 10)},
		"store":       {c.cfg.Datastore},
		"debug":       {"0"},
	}
	if c.cfg.Namespace != "" {
		query.Set("ns", c.cfg.Namespace)
	}

	// Double slash for the same reason as in StartBackup.
	conn, err := c.dialProtocol(ctx, "//api2/json/reader", readerProtocol, query)
	if err != nil {
		return nil, err
	}
	cc, err := startHTTP2(conn)
	if err != nil {
		return nil, err
	}
	return &ReaderSession{client: c, conn: conn, cc: cc, ref: ref}, nil
}

// Ref returns the snapshot this session reads.
func (r *ReaderSession) Ref() SnapshotRef { return r.ref }

// Close closes the connection; open index readers fail afterwards.
func (r *ReaderSession) Close() error { return r.conn.Close() }

func (r *ReaderSession) download(ctx context.Context, name string) ([]byte, error) {
	code, status, body, err := sessionRoundTrip(ctx, r.cc, r.client.addr, http.MethodGet, "/download",
		url.Values{"file-name": {name}}, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, statusError("downloading "+name, status, code, body)
	}
	return body, nil
}

// Manifest returns the snapshot manifest. With Config.Crypt set, a manifest
// written with another key or with a bad signature is refused.
func (r *ReaderSession) Manifest(ctx context.Context) (SnapshotManifest, error) {
	r.mu.Lock()
	cached := r.manifest
	r.mu.Unlock()
	if cached != nil {
		return *cached, nil
	}

	framed, err := r.download(ctx, "index.json.blob")
	if err != nil {
		return SnapshotManifest{}, err
	}
	raw, err := decodeBlob(framed, nil)
	if err != nil {
		return SnapshotManifest{}, fmt.Errorf("pbs: manifest: %w", err)
	}
	var m backupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return SnapshotManifest{}, fmt.Errorf("pbs: decoding manifest: %w", err)
	}
	if m.BackupType != r.ref.Type || m.BackupID != r.ref.ID || m.BackupTime != r.ref.Time.Unix() {
		return SnapshotManifest{}, fmt.Errorf("pbs: manifest is for %s/%s/%d, not the requested snapshot",
			m.BackupType, m.BackupID, m.BackupTime)
	}
	if cs := r.client.crypt; cs != nil {
		if err := verifyManifest(raw, m, cs); err != nil {
			return SnapshotManifest{}, err
		}
	}

	out := &SnapshotManifest{Ref: r.ref, Files: m.Files}
	r.mu.Lock()
	r.manifest = out
	r.mu.Unlock()
	return *out, nil
}

func verifyManifest(raw []byte, m backupManifest, cs *cryptState) error {
	fp, _ := m.Unprotected["key-fingerprint"].(string)
	if fp != "" && !strings.EqualFold(fp, cs.fingerprintHex()) {
		return fmt.Errorf("pbs: wrong key: snapshot was written with key %s, configured key is %s",
			fp, cs.fingerprintHex())
	}
	sigHex, _ := m.Signature.(string)
	if sigHex == "" {
		return fmt.Errorf("pbs: manifest is not signed, but a key is configured")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("pbs: manifest signature is not hex")
	}
	canon, err := canonicalManifestBytes(raw)
	if err != nil {
		return err
	}
	want := cs.authTag(canon)
	if !hmac.Equal(sig, want[:]) {
		return fmt.Errorf("pbs: manifest signature mismatch")
	}
	return nil
}

func (r *ReaderSession) manifestFile(ctx context.Context, name, suffix string) (ManifestFile, error) {
	if !strings.HasSuffix(name, suffix) {
		name += suffix
	}
	m, err := r.Manifest(ctx)
	if err != nil {
		return ManifestFile{}, err
	}
	f, ok := m.file(name)
	if !ok {
		return ManifestFile{}, fmt.Errorf("%w: %s is not in the snapshot", ErrNotFound, name)
	}
	return f, nil
}

// DownloadBlob returns the decoded content of a .blob file, verified against
// the manifest. ".blob" is appended to name when missing.
func (r *ReaderSession) DownloadBlob(ctx context.Context, name string) ([]byte, error) {
	f, err := r.manifestFile(ctx, name, ".blob")
	if err != nil {
		return nil, err
	}
	framed, err := r.download(ctx, f.Filename)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(framed)
	if uint64(len(framed)) != f.Size || hex.EncodeToString(sum[:]) != f.Csum {
		return nil, fmt.Errorf("pbs: %s does not match the manifest (size or checksum)", f.Filename)
	}
	data, err := decodeBlob(framed, r.client.crypt)
	if err != nil {
		return nil, fmt.Errorf("pbs: %s: %w", f.Filename, err)
	}
	return data, nil
}

// OpenDynamicIndex streams the content of a .didx file, verified against the
// manifest. ".didx" is appended to name when missing. A verification failure
// is returned from Read, never io.EOF. ctx bounds the whole stream; Close
// releases its goroutines.
func (r *ReaderSession) OpenDynamicIndex(ctx context.Context, name string) (io.ReadCloser, error) {
	f, err := r.manifestFile(ctx, name, ".didx")
	if err != nil {
		return nil, err
	}
	keyed := f.CryptMode == string(CryptModeEncrypt)
	if keyed && r.client.crypt == nil {
		return nil, fmt.Errorf("pbs: %s is encrypted but no key is configured", f.Filename)
	}

	raw, err := r.download(ctx, f.Filename)
	if err != nil {
		return nil, err
	}
	entries, err := ParseDynamicIndex(raw)
	if err != nil {
		return nil, fmt.Errorf("pbs: %s: %w", f.Filename, err)
	}
	csum := sha256.New()
	var prev uint64
	for _, e := range entries {
		if e.EndOffset <= prev {
			return nil, fmt.Errorf("pbs: %s: chunk end offsets are not ascending", f.Filename)
		}
		prev = e.EndOffset
		binary.Write(csum, binary.LittleEndian, e.EndOffset)
		csum.Write(e.Digest[:])
	}
	if hex.EncodeToString(csum.Sum(nil)) != f.Csum {
		return nil, fmt.Errorf("pbs: %s: index checksum does not match the manifest", f.Filename)
	}

	workers := r.client.cfg.Workers
	if workers == 0 {
		workers = 4
	}
	sctx, cancel := context.WithCancel(ctx)
	ir := &indexReader{
		ctx:     sctx,
		cancel:  cancel,
		name:    f.Filename,
		size:    f.Size,
		entries: len(entries),
		queue:   make(chan chan chunkResult, workers),
	}
	ir.wg.Add(1)
	go ir.produce(r, entries, keyed)
	return ir, nil
}

type chunkResult struct {
	data []byte
	err  error
}

// Result channels are queued in index order, so fetches run concurrently
// while Read stays ordered; the queue capacity bounds memory.
type indexReader struct {
	ctx     context.Context
	cancel  context.CancelFunc
	name    string
	size    uint64
	entries int
	queue   chan chan chunkResult
	wg      sync.WaitGroup

	cur      []byte
	consumed int
	read     uint64
	err      error
}

func (ir *indexReader) produce(r *ReaderSession, entries []IndexEntry, keyed bool) {
	defer ir.wg.Done()
	defer close(ir.queue)
	var start uint64
	for _, e := range entries {
		res := make(chan chunkResult, 1)
		select {
		case ir.queue <- res:
		case <-ir.ctx.Done():
			return
		}
		ir.wg.Add(1)
		go func(e IndexEntry, start uint64) {
			defer ir.wg.Done()
			data, err := r.fetchChunk(ir.ctx, ir.name, e, e.EndOffset-start, keyed)
			res <- chunkResult{data, err}
		}(e, start)
		start = e.EndOffset
	}
}

func (r *ReaderSession) fetchChunk(ctx context.Context, name string, e IndexEntry, size uint64, keyed bool) ([]byte, error) {
	digest := hex.EncodeToString(e.Digest[:])
	code, status, framed, err := sessionRoundTrip(ctx, r.cc, r.client.addr, http.MethodGet, "/chunk",
		url.Values{"digest": {digest}}, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, statusError("downloading chunk "+digest, status, code, framed)
	}
	plain, err := decodeBlob(framed, r.client.crypt)
	if err != nil {
		return nil, fmt.Errorf("pbs: %s: chunk %s: %w", name, digest, err)
	}
	if uint64(len(plain)) != size {
		return nil, fmt.Errorf("pbs: %s: chunk %s has %d bytes, index says %d", name, digest, len(plain), size)
	}
	var got [32]byte
	if keyed {
		got = r.client.crypt.computeDigest(plain)
	} else {
		got = sha256.Sum256(plain)
	}
	if got != e.Digest {
		return nil, fmt.Errorf("pbs: %s: chunk %s digest mismatch", name, digest)
	}
	return plain, nil
}

func (ir *indexReader) Read(p []byte) (int, error) {
	for len(ir.cur) == 0 {
		if ir.err != nil {
			return 0, ir.err
		}
		res, ok := <-ir.queue
		if !ok {
			switch {
			case ir.consumed != ir.entries:
				ir.err = fmt.Errorf("pbs: reading %s: %w", ir.name, context.Cause(ir.ctx))
			case ir.read != ir.size:
				ir.err = fmt.Errorf("pbs: %s: read %d bytes, manifest says %d", ir.name, ir.read, ir.size)
			default:
				ir.err = io.EOF
			}
			continue
		}
		c := <-res
		if c.err != nil {
			ir.err = c.err
			ir.cancel()
			continue
		}
		ir.consumed++
		ir.cur = c.data
	}
	n := copy(p, ir.cur)
	ir.cur = ir.cur[n:]
	ir.read += uint64(n)
	return n, nil
}

func (ir *indexReader) Close() error {
	ir.cancel()
	ir.wg.Wait()
	return nil
}
