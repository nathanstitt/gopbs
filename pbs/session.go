package pbs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const backupProtocol = "proxmox-backup-protocol-v1"

// ErrNoPrevious reports that the server has no previous snapshot index for
// the requested archive.
var ErrNoPrevious = errors.New("pbs: no previous index")

// BackupSession is one open backup-protocol connection: one session writes
// exactly one snapshot. It is bound to a single HTTP/2 connection — a
// connection loss fails the session rather than silently opening a second
// one (a defect in the reference client; ARCHITECTURE.md §12).
//
// Index and blob methods are safe for concurrent use; Finish and Abort are
// not, and must be called once, after all uploads completed.
type BackupSession struct {
	client *Client
	conn   net.Conn
	cc     *http2.ClientConn
	ref    SnapshotRef

	known *chunkSet // session-wide dedup registry (see upload.go)

	mu       sync.Mutex
	files    []ManifestFile
	byWID    map[uint64]int // writer id -> index into files
	finished bool
}

// ManifestFile is one file entry of a snapshot manifest.
type ManifestFile struct {
	CryptMode string `json:"crypt-mode"` // "none", "encrypt" or "sign-only"
	Csum      string `json:"csum"`       // stored blob's SHA-256, or the index checksum
	Filename  string `json:"filename"`
	Size      uint64 `json:"size"` // stored blob size, or the plain archive size
}

type backupManifest struct {
	BackupID    string         `json:"backup-id"`
	BackupTime  int64          `json:"backup-time"`
	BackupType  string         `json:"backup-type"`
	Files       []ManifestFile `json:"files"`
	Signature   any            `json:"signature"`
	Unprotected map[string]any `json:"unprotected"`
}

// StartBackup opens a backup session: it dials the server, upgrades the
// connection to the backup protocol, and speaks HTTP/2 over it from then on.
func (c *Client) StartBackup(ctx context.Context, ref SnapshotRef) (*BackupSession, error) {
	ref, err := ref.withDefaults()
	if err != nil {
		return nil, err
	}

	query := url.Values{
		"backup-type": {ref.Type},
		"backup-id":   {ref.ID},
		"backup-time": {strconv.FormatInt(ref.Time.Unix(), 10)},
		"store":       {c.cfg.Datastore},
	}
	if c.cfg.Namespace != "" {
		query.Set("ns", c.cfg.Namespace)
	}

	var conn net.Conn
	if c.cfg.DialSession != nil {
		// The caller's dialer hands back a connection that already carries the
		// backup protocol (e.g. a tunnel through a proxy that performed the
		// upgrade with its own credentials).
		conn, err = c.cfg.DialSession(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("pbs: dialing session: %w", err)
		}
	} else {
		// The double slash mirrors proxmox-backup-client's upgrade request
		// verbatim: the real server normalizes it, and pmoxs3backuproxy matches
		// on exactly this prefix.
		conn, err = c.dialProtocol(ctx, "//api2/json/backup", backupProtocol, query)
		if err != nil {
			return nil, err
		}
	}

	cc, err := startHTTP2(conn)
	if err != nil {
		return nil, err
	}

	return &BackupSession{
		client: c,
		conn:   conn,
		cc:     cc,
		ref:    ref,
		known:  newChunkSet(),
		byWID:  make(map[uint64]int),
	}, nil
}

// Ref returns the snapshot identity this session writes, with all defaults
// resolved (the exact values a restore later addresses).
func (s *BackupSession) Ref() SnapshotRef { return s.ref }

// cryptLabel is the manifest crypt-mode for data this session uploads.
func (s *BackupSession) cryptLabel() string {
	if cs := s.client.crypt; cs != nil {
		return string(cs.mode)
	}
	return "none"
}

// ChunkDigest returns the chunk digest for plain under this session's crypt
// mode: SHA-256 of the plaintext normally and in sign-only mode, the keyed
// digest SHA256(plain ‖ id_key) in encrypt mode. Digests — never ciphertext
// — drive deduplication, so identical plaintext under the same key
// deduplicates across backups.
func (s *BackupSession) ChunkDigest(plain []byte) [32]byte {
	if cs := s.client.crypt; cs != nil && cs.mode == CryptModeEncrypt {
		return cs.computeDigest(plain)
	}
	return sha256.Sum256(plain)
}

func (c *Client) dialProtocol(ctx context.Context, path, protocol string, query url.Values) (net.Conn, error) {
	header := make(http.Header)
	if err := c.authHeaders(ctx, header, false); err != nil {
		return nil, err
	}
	header.Set("Upgrade", protocol)
	header.Set("Connection", "Upgrade")
	return c.upgrade(ctx, path+"?"+query.Encode(), header)
}

// startHTTP2 closes conn on failure.
func startHTTP2(conn net.Conn) (*http2.ClientConn, error) {
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("pbs: starting http/2: %w", err)
	}
	return cc, nil
}

// upgrade performs the HTTP/1.1 101 handshake and returns the raw connection
// (with any bytes the server sent after the 101 preserved).
func (c *Client) upgrade(ctx context.Context, path string, header http.Header) (net.Conn, error) {
	dialer := &tls.Dialer{Config: c.tlsConf}
	conn, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("pbs: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	// Cancellation, not only the deadline, must stop the handshake.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	var req bytes.Buffer
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, c.addr)
	for key, values := range header {
		for _, v := range values {
			fmt.Fprintf(&req, "%s: %s\r\n", key, v)
		}
	}
	req.WriteString("\r\n")
	if _, err := conn.Write(req.Bytes()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pbs: sending upgrade request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("pbs: reading upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		conn.Close()
		return nil, statusError("protocol upgrade refused", resp.Status, resp.StatusCode, body)
	}

	if !stop() {
		conn.Close()
		return nil, fmt.Errorf("pbs: protocol upgrade: %w", ctx.Err())
	}
	conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn preserves bytes the bufio.Reader consumed past the 101
// response — the server may start HTTP/2 immediately after it.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// Session endpoints need no auth headers: authentication is bound to the
// connection by the upgrade.
func sessionRoundTrip(ctx context.Context, cc *http2.ClientConn, addr, method, path string, query url.Values, body []byte) (int, string, []byte, error) {
	u := &url.URL{Scheme: "https", Host: addr, Path: path, RawQuery: query.Encode()}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, fmt.Errorf("pbs: %w", err)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("pbs: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", nil, fmt.Errorf("pbs: %s %s: reading response: %w", method, path, err)
	}
	return resp.StatusCode, resp.Status, respBody, nil
}

func (s *BackupSession) roundTrip(ctx context.Context, method, path string, query url.Values, body []byte) ([]byte, error) {
	code, status, respBody, err := sessionRoundTrip(ctx, s.cc, s.client.addr, method, path, query, body)
	if err != nil {
		return nil, err
	}
	if code < 200 || code > 299 {
		// "No previous backup" is not an error condition. The real server
		// reports a missing previous snapshot as 400 "no valid previous
		// backup", and a previous snapshot that lacks the requested archive
		// (e.g. the first v2 backup on an id with v1 history) as 400
		// `Unable to open dynamic index ... - No such file or directory`;
		// pmoxs3backuproxy uses a plain 404 for both.
		// TODO: Open PR?
		if path == "/previous" && code == http.StatusNotFound {
			return nil, ErrNoPrevious
		}
		if path == "/previous" && code == http.StatusBadRequest {
			msg := string(respBody)
			if strings.Contains(msg, "no valid previous backup") ||
				(strings.Contains(msg, "Unable to open") &&
					strings.Contains(msg, "No such file or directory")) {
				return nil, ErrNoPrevious
			}
		}
		return nil, statusError(method+" "+path, status, code, respBody)
	}
	return respBody, nil
}

// CreateDynamicIndex opens a dynamic-index writer for the named archive
// (e.g. "root.pxar.didx") and returns its writer id. Parameters are sent
// both as a query string and as a JSON body: the real server requires the
// body, pmoxs3backuproxy reads only the query, and each ignores the other's
// encoding.
func (s *BackupSession) CreateDynamicIndex(ctx context.Context, name string) (uint64, error) {
	body, err := json.Marshal(map[string]string{"archive-name": name})
	if err != nil {
		return 0, fmt.Errorf("pbs: %w", err)
	}
	resp, err := s.roundTrip(ctx, http.MethodPost, "/dynamic_index",
		url.Values{"archive-name": {name}}, body)
	if err != nil {
		return 0, err
	}
	var parsed struct {
		Data uint64 `json:"data"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return 0, fmt.Errorf("pbs: decoding dynamic_index response: %w", err)
	}

	s.mu.Lock()
	s.byWID[parsed.Data] = len(s.files)
	s.files = append(s.files, ManifestFile{Filename: name, CryptMode: s.cryptLabel()})
	s.mu.Unlock()
	return parsed.Data, nil
}

// AppendDynamicIndex registers uploaded chunks with an index: digests are
// lowercase hex, offsets the chunk START positions within the archive
// stream. At most 128 chunks per call (the server rejects oversized
// requests); the Upload* helpers batch accordingly.
func (s *BackupSession) AppendDynamicIndex(ctx context.Context, wid uint64, digests []string, offsets []uint64) error {
	if len(digests) != len(offsets) {
		return fmt.Errorf("pbs: %d digests for %d offsets", len(digests), len(offsets))
	}
	body, err := json.Marshal(map[string]any{
		"wid":         wid,
		"digest-list": digests,
		"offset-list": offsets,
	})
	if err != nil {
		return fmt.Errorf("pbs: %w", err)
	}
	_, err = s.roundTrip(ctx, http.MethodPut, "/dynamic_index", nil, body)
	return err
}

// CloseDynamicIndex finishes an index: csum is the index checksum (sha256
// over per-chunk LE end-offset ‖ digest), size the total byte count,
// chunkCount the number of index entries.
func (s *BackupSession) CloseDynamicIndex(ctx context.Context, wid uint64, csum [32]byte, size, chunkCount uint64) error {
	// Dual-encoded for the same reason as CreateDynamicIndex.
	query := url.Values{
		"wid":         {strconv.FormatUint(wid, 10)},
		"csum":        {hex.EncodeToString(csum[:])},
		"size":        {strconv.FormatUint(size, 10)},
		"chunk-count": {strconv.FormatUint(chunkCount, 10)},
	}
	body, err := json.Marshal(map[string]any{
		"wid":         wid,
		"csum":        hex.EncodeToString(csum[:]),
		"size":        size,
		"chunk-count": chunkCount,
	})
	if err != nil {
		return fmt.Errorf("pbs: %w", err)
	}
	if _, err := s.roundTrip(ctx, http.MethodPost, "/dynamic_close", query, body); err != nil {
		return err
	}

	s.mu.Lock()
	if i, ok := s.byWID[wid]; ok {
		s.files[i].Csum = hex.EncodeToString(csum[:])
		s.files[i].Size = size
	}
	s.mu.Unlock()
	return nil
}

// UploadDynamicChunk uploads one content chunk (plaintext; framing,
// compression and encryption are handled here) for the given index writer.
// digest must be ChunkDigest(plain).
func (s *BackupSession) UploadDynamicChunk(ctx context.Context, enc *BlobEncoder, wid uint64, digest [32]byte, plain []byte) error {
	var framed []byte
	if cs := s.client.crypt; cs != nil && cs.mode == CryptModeEncrypt {
		var err error
		if framed, err = enc.encodeEncrypted(plain, true, cs.aead); err != nil {
			return err
		}
	} else {
		framed = enc.Encode(plain, true)
	}
	query := url.Values{
		"digest":       {hex.EncodeToString(digest[:])},
		"encoded-size": {strconv.Itoa(len(framed))},
		"size":         {strconv.Itoa(len(plain))},
		"wid":          {strconv.FormatUint(wid, 10)},
	}
	_, err := s.roundTrip(ctx, http.MethodPost, "/dynamic_chunk", query, framed)
	return err
}

// UploadBlob frames data as a blob (optionally zstd-compressed, encrypted
// when the session has a key in encrypt mode), uploads it under filename
// (e.g. "pct.conf.blob"), and records it in the manifest with the size and
// sha256 of the encoded blob as stored by the server (matching the
// reference client — the restore path verifies both against the stored
// file).
func (s *BackupSession) UploadBlob(ctx context.Context, enc *BlobEncoder, filename string, data []byte, compress bool) error {
	var framed []byte
	if cs := s.client.crypt; cs != nil && cs.mode == CryptModeEncrypt {
		var err error
		if framed, err = enc.encodeEncrypted(data, compress, cs.aead); err != nil {
			return err
		}
	} else {
		framed = enc.Encode(data, compress)
	}
	return s.putBlob(ctx, filename, framed, s.cryptLabel())
}

// putBlob uploads an already-framed blob and records it in the manifest
// under the given crypt-mode label. Framing and label are decoupled because
// two special blobs mismatch on purpose: "rsa-encrypted.key.blob" is framed
// plain but labeled "encrypt", and "index.json.blob" is always plain with
// label "none".
func (s *BackupSession) putBlob(ctx context.Context, filename string, framed []byte, label string) error {
	query := url.Values{
		"file-name":    {filename},
		"encoded-size": {strconv.Itoa(len(framed))},
	}
	if _, err := s.roundTrip(ctx, http.MethodPost, "/blob", query, framed); err != nil {
		return err
	}

	sum := sha256.Sum256(framed)
	s.mu.Lock()
	s.files = append(s.files, ManifestFile{
		Filename:  filename,
		Size:      uint64(len(framed)),
		Csum:      hex.EncodeToString(sum[:]),
		CryptMode: label,
	})
	s.mu.Unlock()
	return nil
}

// DownloadPrevious fetches the previous snapshot's raw index for the named
// archive, for chunk deduplication. Returns ErrNoPrevious when this is the
// first backup. Digests of a well-formed index are registered with the
// session's dedup set as a side effect (the server registers them as known
// to the session at the same time).
func (s *BackupSession) DownloadPrevious(ctx context.Context, archiveName string) ([]byte, error) {
	raw, err := s.roundTrip(ctx, http.MethodGet, "/previous", url.Values{"archive-name": {archiveName}}, nil)
	if err != nil {
		return nil, err
	}
	if entries, err := ParseDynamicIndex(raw); err == nil {
		for _, e := range entries {
			s.known.seed(e.Digest)
		}
	}
	return raw, nil
}

// PreviousIndex downloads and parses the previous snapshot's index for the
// named archive (registering its chunks as known, like DownloadPrevious).
// Metadata change detection needs the payload index's chunk layout before
// generation starts, and the metadata index to validate a local copy of the
// previous metadata stream.
func (s *BackupSession) PreviousIndex(ctx context.Context, archiveName string) ([]IndexEntry, error) {
	raw, err := s.DownloadPrevious(ctx, archiveName)
	if err != nil {
		return nil, err
	}
	return ParseDynamicIndex(raw)
}

// Finish uploads the manifest, commits the snapshot and closes the
// connection. With a key configured the manifest is signed (and carries the
// key fingerprint); with a master key, the wrapped encryption key is
// uploaded alongside so its holder can recover the data. The session is
// unusable afterwards.
func (s *BackupSession) Finish(ctx context.Context) error {
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return fmt.Errorf("pbs: session already finished")
	}
	s.mu.Unlock()

	cs := s.client.crypt
	if cs != nil && cs.masterKey != nil {
		wrapped, err := wrapKeyConfig(cs, time.Now())
		if err != nil {
			return err
		}
		// The RSA ciphertext is framed plain (it is already opaque) but
		// recorded as "encrypt", matching proxmox-backup-client; uploaded
		// before the manifest is built so the signature covers it.
		framed := NewBlobEncoder().Encode(wrapped, false)
		if err := s.putBlob(ctx, "rsa-encrypted.key.blob", framed, string(CryptModeEncrypt)); err != nil {
			return err
		}
	}

	s.mu.Lock()
	manifest := backupManifest{
		BackupID:    s.ref.ID,
		BackupTime:  s.ref.Time.Unix(),
		BackupType:  s.ref.Type,
		Files:       s.files,
		Unprotected: map[string]any{},
	}
	s.mu.Unlock()

	if cs != nil {
		canon, err := canonicalManifestJSON(manifest)
		if err != nil {
			return err
		}
		sig := cs.authTag(canon)
		manifest.Signature = hex.EncodeToString(sig[:])
		// Deliberately outside the signed portion, matching upstream.
		manifest.Unprotected["key-fingerprint"] = cs.fingerprintHex()
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("pbs: encoding manifest: %w", err)
	}
	// The manifest blob is stored uncompressed and never encrypted, matching
	// the reference clients; the signature travels inside it.
	if err := s.putBlob(ctx, "index.json.blob", NewBlobEncoder().Encode(data, false), "none"); err != nil {
		return err
	}
	if _, err := s.roundTrip(ctx, http.MethodPost, "/finish", nil, nil); err != nil {
		return err
	}

	s.mu.Lock()
	s.finished = true
	s.mu.Unlock()
	return s.conn.Close()
}

// Abort closes the connection without committing; the server discards the
// unfinished snapshot.
func (s *BackupSession) Abort() error {
	s.mu.Lock()
	s.finished = true
	s.mu.Unlock()
	return s.conn.Close()
}
