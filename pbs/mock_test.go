package pbs_test

// An in-process mock PBS server: a TLS listener that answers the regular
// API's ticket login and snapshot listing, performs the backup- and
// reader-protocol 101 upgrades, then serves the session endpoints over
// HTTP/2 — verifying chunk framing (magic, CRC, compression, digest) as the
// real server would, and recording everything for assertions.

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"
)

type mockIndex struct {
	name       string
	digests    []string
	offsets    []uint64
	closed     bool
	csum       string
	size       uint64
	chunkCount uint64
}

type mockSnapshot struct {
	ns, typ, id string
	time        int64
	files       map[string][]byte // file name -> stored bytes (blob or didx)
	sizes       map[string]uint64 // file name -> manifest size
}

type mockSession struct {
	ns, typ, id string
	time        int64
	wids        []uint64
	blobs       map[string][]byte // encoded, as stored
	snap        *mockSnapshot     // reader sessions only
	allowed     map[string]bool   // reader: chunks of downloaded indexes
}

type mockPBS struct {
	t           *testing.T
	ln          net.Listener
	fingerprint string
	baseURL     string

	zdec *zstd.Decoder

	// cryptKey/idKey let the mock verify encrypted uploads the way the
	// client-side spec says a reader would; set via setCryptKey.
	cryptKey *[32]byte
	idKey    [32]byte

	mu           sync.Mutex
	loginCount   int
	upgradeReqs  []*http.Request
	sessions     []net.Conn
	nextWID      uint64
	indexes      map[uint64]*mockIndex
	chunks       map[string][]byte // digest hex -> plaintext
	known        map[string]bool   // uploaded or registered via /previous
	chunkDelay   func(digestHex string) time.Duration
	blobs        map[string][]byte // file name -> decoded payload
	blobsEncoded map[string][]byte // file name -> encoded blob as stored
	previous     map[string][]byte // archive name -> raw didx
	finished     bool
	failUpgrade  int            // respond with this status instead of 101
	rejectAuth   bool           // answer every request with 401
	failPath     map[string]int // h2 path -> status for the next call

	// previousMissingStatus/Msg override the response for a /previous
	// request on an archive with no registered previous index (default:
	// pmoxs3-style plain 404). The real server answers 400 with a message
	// depending on whether the snapshot or just the archive is missing.
	previousMissingStatus int
	previousMissingMsg    string

	chunksEncoded map[string][]byte // digest hex -> framed chunk as stored
	snapshots     []*mockSnapshot   // committed at /finish
}

func newMockPBS(t *testing.T) *mockPBS {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-pbs"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}

	m := &mockPBS{
		t:            t,
		ln:           ln,
		fingerprint:  hex.EncodeToString(sum[:]),
		baseURL:      "https://" + ln.Addr().String(),
		zdec:         dec,
		nextWID:      1,
		indexes:      make(map[uint64]*mockIndex),
		chunks:       make(map[string][]byte),
		known:        make(map[string]bool),
		blobs:        make(map[string][]byte),
		blobsEncoded: make(map[string][]byte),
		previous:     make(map[string][]byte),
		failPath:     make(map[string]int),

		chunksEncoded: make(map[string][]byte),
	}
	go m.serve()
	t.Cleanup(func() { ln.Close(); dec.Close() })
	return m
}

func (m *mockPBS) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handleConn(conn)
	}
}

func (m *mockPBS) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		m.mu.Lock()
		reject := m.rejectAuth
		m.mu.Unlock()
		if reject {
			// Echo the credentials like a careless server, to prove the
			// client keeps them out of errors.
			body := "authentication failure: " + req.Header.Get("Authorization") + req.Header.Get("Cookie")
			fmt.Fprintf(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				len(body), body)
			return
		}
		switch {
		case req.URL.Path == "/api2/json/access/ticket":
			m.handleTicket(conn, req)
			return // Connection: close
		case strings.HasSuffix(req.URL.Path, "/api2/json/backup"):
			m.handleUpgrade(conn, req)
			return
		case strings.HasSuffix(req.URL.Path, "/api2/json/reader"):
			m.handleReaderUpgrade(conn, req)
			return
		case req.Method == http.MethodGet &&
			strings.HasPrefix(req.URL.Path, "/api2/json/admin/datastore/") &&
			strings.HasSuffix(req.URL.Path, "/snapshots"):
			m.handleListSnapshots(conn, req)
			return
		default:
			fmt.Fprintf(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
	}
}

func (m *mockPBS) handleTicket(conn net.Conn, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		return
	}
	m.mu.Lock()
	m.loginCount++
	m.mu.Unlock()

	if req.PostFormValue("password") != "hunter2" {
		fmt.Fprintf(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	body, _ := json.Marshal(map[string]any{"data": map[string]string{
		"ticket":              "PBS:user@pam:TICKETDATA==",
		"CSRFPreventionToken": "CSRFTOKEN",
	}})
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

func (m *mockPBS) handleUpgrade(conn net.Conn, req *http.Request) {
	m.mu.Lock()
	m.upgradeReqs = append(m.upgradeReqs, req)
	fail := m.failUpgrade
	m.mu.Unlock()

	if fail != 0 {
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrefused",
			fail, http.StatusText(fail))
		return
	}
	if req.Header.Get("Upgrade") != "proxmox-backup-protocol-v1" {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: proxmox-backup-protocol-v1\r\nConnection: Upgrade\r\n\r\n")

	m.mu.Lock()
	m.sessions = append(m.sessions, conn)
	m.mu.Unlock()

	sess := newMockSession(req.URL.Query())
	sess.blobs = make(map[string][]byte)
	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.handleH2(sess, w, r) }),
	})
}

func newMockSession(q url.Values) *mockSession {
	t, _ := strconv.ParseInt(q.Get("backup-time"), 10, 64)
	return &mockSession{ns: q.Get("ns"), typ: q.Get("backup-type"), id: q.Get("backup-id"), time: t}
}

// Callers hold m.mu.
func (m *mockPBS) findSnapshot(ns, typ, id string, time int64) *mockSnapshot {
	for _, s := range m.snapshots {
		if s.ns == ns && s.typ == typ && s.id == id && s.time == time {
			return s
		}
	}
	return nil
}

// Callers hold m.mu.
func (m *mockPBS) lastSnapshot(ns, typ, id string, before int64) *mockSnapshot {
	var last *mockSnapshot
	for _, s := range m.snapshots {
		if s.ns == ns && s.typ == typ && s.id == id && s.time < before && (last == nil || s.time > last.time) {
			last = s
		}
	}
	return last
}

// Callers hold m.mu.
func (m *mockPBS) commit(sess *mockSession) error {
	snap := &mockSnapshot{
		ns: sess.ns, typ: sess.typ, id: sess.id, time: sess.time,
		files: make(map[string][]byte),
		sizes: make(map[string]uint64),
	}
	for name, b := range sess.blobs {
		snap.files[name] = b
		snap.sizes[name] = uint64(len(b))
	}
	for _, wid := range sess.wids {
		idx := m.indexes[wid]
		if !idx.closed {
			return fmt.Errorf("index %s not closed", idx.name)
		}
		out := make([]byte, 4096, 4096+40*len(idx.digests))
		copy(out, []byte{28, 145, 78, 165, 25, 186, 179, 205})
		for i, d := range idx.digests {
			end := idx.size
			if i+1 < len(idx.offsets) {
				end = idx.offsets[i+1]
			}
			raw, _ := hex.DecodeString(d)
			out = binary.LittleEndian.AppendUint64(out, end)
			out = append(out, raw...)
		}
		snap.files[idx.name] = out
		snap.sizes[idx.name] = idx.size
	}
	if m.findSnapshot(snap.ns, snap.typ, snap.id, snap.time) != nil {
		return fmt.Errorf("snapshot exists")
	}
	m.snapshots = append(m.snapshots, snap)
	return nil
}

func (m *mockPBS) handleReaderUpgrade(conn net.Conn, req *http.Request) {
	m.mu.Lock()
	m.upgradeReqs = append(m.upgradeReqs, req)
	sess := newMockSession(req.URL.Query())
	sess.snap = m.findSnapshot(sess.ns, sess.typ, sess.id, sess.time)
	sess.allowed = make(map[string]bool)
	m.mu.Unlock()

	if req.Header.Get("Upgrade") != "proxmox-backup-reader-protocol-v1" {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if sess.snap == nil {
		fmt.Fprintf(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 18\r\nConnection: close\r\n\r\nno such snapshot\r\n")
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: proxmox-backup-reader-protocol-v1\r\nConnection: Upgrade\r\n\r\n")

	m.mu.Lock()
	m.sessions = append(m.sessions, conn)
	m.mu.Unlock()

	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.handleReaderH2(sess, w, r) }),
	})
}

func (m *mockPBS) handleReaderH2(sess *mockSession, w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.Method + " " + r.URL.Path {
	case "GET /download":
		name := r.URL.Query().Get("file-name")
		data, ok := sess.snap.files[name]
		if !ok {
			httpError(w, 404, "no file %s", name)
			return
		}
		// The real server serves only chunks of downloaded indexes.
		if strings.HasSuffix(name, ".didx") {
			for i := 4096; i+40 <= len(data); i += 40 {
				sess.allowed[hex.EncodeToString(data[i+8:i+40])] = true
			}
		}
		w.Write(data)

	case "GET /chunk":
		d := r.URL.Query().Get("digest")
		if !sess.allowed[d] {
			httpError(w, 400, "chunk %s not in a downloaded index", d)
			return
		}
		data, ok := m.chunksEncoded[d]
		if !ok {
			httpError(w, 404, "no chunk %s", d)
			return
		}
		w.Write(data)

	default:
		httpError(w, 404, "mock: no reader endpoint %s %s", r.Method, r.URL.Path)
	}
}

func (m *mockPBS) handleListSnapshots(conn net.Conn, req *http.Request) {
	q := req.URL.Query()
	type file struct {
		Filename  string `json:"filename"`
		Size      uint64 `json:"size"`
		CryptMode string `json:"crypt-mode"`
	}
	type entry struct {
		Type      string `json:"backup-type"`
		ID        string `json:"backup-id"`
		Time      int64  `json:"backup-time"`
		Size      uint64 `json:"size"`
		Protected bool   `json:"protected"`
		Files     []file `json:"files"`
	}
	data := []entry{}
	m.mu.Lock()
	for _, s := range m.snapshots {
		if s.ns != q.Get("ns") ||
			(q.Get("backup-type") != "" && s.typ != q.Get("backup-type")) ||
			(q.Get("backup-id") != "" && s.id != q.Get("backup-id")) {
			continue
		}
		e := entry{Type: s.typ, ID: s.id, Time: s.time}
		for name, size := range s.sizes {
			e.Files = append(e.Files, file{Filename: name, Size: size, CryptMode: "none"})
			e.Size += size
		}
		sort.Slice(e.Files, func(i, j int) bool { return e.Files[i].Filename < e.Files[j].Filename })
		data = append(data, e)
	}
	m.mu.Unlock()

	body, _ := json.Marshal(map[string]any{"data": data})
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

func (m *mockPBS) dropSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.sessions {
		c.Close()
	}
	m.sessions = nil
}

func httpError(w http.ResponseWriter, code int, format string, args ...any) {
	w.WriteHeader(code)
	fmt.Fprintf(w, format, args...)
}

func (m *mockPBS) handleH2(sess *mockSession, w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	if code, ok := m.failPath[r.URL.Path]; ok {
		delete(m.failPath, r.URL.Path)
		m.mu.Unlock()
		httpError(w, code, "mock failure for %s", r.URL.Path)
		return
	}
	m.mu.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, 500, "body: %v", err)
		return
	}

	switch r.Method + " " + r.URL.Path {
	case "POST /dynamic_index":
		// The proxmox-S3-server we use for testing has a slightly different API than the real server
		// We have to send the archive name both ways for it to accept the request.
		// TODO: Open a pull request for this to be fixed
		name := r.URL.Query().Get("archive-name")
		if name == "" {
			httpError(w, 400, "create without archive-name query parameter")
			return
		}
		var fromBody struct {
			Name string `json:"archive-name"`
		}
		if err := json.Unmarshal(body, &fromBody); err != nil || fromBody.Name != name {
			httpError(w, 400, "create body %q does not carry matching archive-name", body)
			return
		}
		in := struct{ Name string }{name}
		m.mu.Lock()
		wid := m.nextWID
		m.nextWID++
		m.indexes[wid] = &mockIndex{name: in.Name}
		sess.wids = append(sess.wids, wid)
		m.mu.Unlock()
		fmt.Fprintf(w, `{"data":%d}`, wid)

	case "PUT /dynamic_index":
		var in struct {
			WID     uint64   `json:"wid"`
			Digests []string `json:"digest-list"`
			Offsets []uint64 `json:"offset-list"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			httpError(w, 400, "bad append body")
			return
		}
		if len(in.Digests) != len(in.Offsets) || len(in.Digests) == 0 || len(in.Digests) > 128 {
			httpError(w, 400, "bad append lengths: %d/%d", len(in.Digests), len(in.Offsets))
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		idx, ok := m.indexes[in.WID]
		if !ok || idx.closed {
			httpError(w, 400, "unknown or closed wid %d", in.WID)
			return
		}
		for _, d := range in.Digests {
			if !m.known[d] {
				httpError(w, 400, "append references unknown chunk %s", d)
				return
			}
		}
		idx.digests = append(idx.digests, in.Digests...)
		idx.offsets = append(idx.offsets, in.Offsets...)

	case "POST /dynamic_close":
		q := r.URL.Query()
		var in struct {
			WID        uint64
			Csum       string
			Size       uint64
			ChunkCount uint64
		}
		var perr error
		if in.WID, perr = strconv.ParseUint(q.Get("wid"), 10, 64); perr != nil {
			httpError(w, 400, "close without wid query parameter")
			return
		}
		in.Csum = q.Get("csum")
		if in.Size, perr = strconv.ParseUint(q.Get("size"), 10, 64); perr != nil {
			httpError(w, 400, "close without size query parameter")
			return
		}
		if in.ChunkCount, perr = strconv.ParseUint(q.Get("chunk-count"), 10, 64); perr != nil {
			httpError(w, 400, "close without chunk-count query parameter")
			return
		}
		var fromBody struct {
			WID        uint64 `json:"wid"`
			Csum       string `json:"csum"`
			Size       uint64 `json:"size"`
			ChunkCount uint64 `json:"chunk-count"`
		}
		if err := json.Unmarshal(body, &fromBody); err != nil ||
			fromBody.WID != in.WID || fromBody.Csum != in.Csum ||
			fromBody.Size != in.Size || fromBody.ChunkCount != in.ChunkCount {
			httpError(w, 400, "close body %q does not match query parameters", body)
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		idx, ok := m.indexes[in.WID]
		if !ok || idx.closed {
			httpError(w, 400, "unknown or closed wid %d", in.WID)
			return
		}
		if uint64(len(idx.digests)) != in.ChunkCount {
			httpError(w, 400, "chunk-count %d, appended %d", in.ChunkCount, len(idx.digests))
			return
		}
		idx.closed, idx.csum, idx.size, idx.chunkCount = true, in.Csum, in.Size, in.ChunkCount

	case "POST /dynamic_chunk":
		q := r.URL.Query()
		m.mu.Lock()
		delay := m.chunkDelay
		m.mu.Unlock()
		if delay != nil {
			time.Sleep(delay(q.Get("digest")))
		}
		plain, encrypted, err := m.decodeBlob(body)
		if err != nil {
			httpError(w, 400, "chunk: %v", err)
			return
		}
		if enc, _ := strconv.Atoi(q.Get("encoded-size")); enc != len(body) {
			httpError(w, 400, "encoded-size %d, body %d", enc, len(body))
			return
		}
		if size, _ := strconv.Atoi(q.Get("size")); size != len(plain) {
			httpError(w, 400, "size %d, plaintext %d", size, len(plain))
			return
		}
		// The real server trusts encrypted digests; the mock recomputes the
		// keyed digest SHA256(plain || id_key) to catch a client that frames
		// encrypted but digests plain (or vice versa).
		h := sha256.New()
		h.Write(plain)
		if encrypted {
			h.Write(m.idKey[:])
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != q.Get("digest") {
			httpError(w, 400, "digest %s, content hashes to %s", q.Get("digest"), got)
			return
		}
		m.mu.Lock()
		m.chunks[q.Get("digest")] = plain
		m.chunksEncoded[q.Get("digest")] = append([]byte(nil), body...)
		m.known[q.Get("digest")] = true
		m.mu.Unlock()

	case "POST /blob":
		q := r.URL.Query()
		payload, _, err := m.decodeBlob(body)
		if err != nil {
			httpError(w, 400, "blob: %v", err)
			return
		}
		if enc, _ := strconv.Atoi(q.Get("encoded-size")); enc != len(body) {
			httpError(w, 400, "encoded-size %d, body %d", enc, len(body))
			return
		}
		m.mu.Lock()
		m.blobs[q.Get("file-name")] = payload
		m.blobsEncoded[q.Get("file-name")] = append([]byte(nil), body...)
		sess.blobs[q.Get("file-name")] = append([]byte(nil), body...)
		m.mu.Unlock()

	case "GET /previous":
		m.mu.Lock()
		name := r.URL.Query().Get("archive-name")
		data, ok := m.previous[name]
		if !ok {
			// As on the real server.
			if last := m.lastSnapshot(sess.ns, sess.typ, sess.id, sess.time); last != nil {
				data, ok = last.files[name]
			}
		}
		if ok {
			// Like the real server, downloading the previous index makes
			// its chunks known to the session.
			for i := 4096; i+40 <= len(data); i += 40 {
				m.known[hex.EncodeToString(data[i+8:i+40])] = true
			}
		}
		missingStatus, missingMsg := m.previousMissingStatus, m.previousMissingMsg
		m.mu.Unlock()
		if !ok {
			if missingStatus != 0 {
				httpError(w, missingStatus, "%s", missingMsg)
			} else {
				httpError(w, 404, "no previous backup")
			}
			return
		}
		w.Write(data)

	case "POST /finish":
		m.mu.Lock()
		defer m.mu.Unlock()
		if err := m.commit(sess); err != nil {
			httpError(w, 400, "finish: %v", err)
			return
		}
		m.finished = true

	default:
		httpError(w, 404, "mock: no endpoint %s %s", r.Method, r.URL.Path)
	}
}

// decodeBlob validates blob framing exactly as the server would: magic,
// CRC32 over the payload, zstd for the compressed magics. Encrypted blobs
// (44-byte header, CRC over the ciphertext only) are decrypted with the
// mock's key — an independent reimplementation of the client's framing, so
// the two can't share a bug. The second result reports whether the frame was
// encrypted.
func (m *mockPBS) decodeBlob(framed []byte) ([]byte, bool, error) {
	if len(framed) < 12 {
		return nil, false, fmt.Errorf("framed blob too short: %d", len(framed))
	}
	encrypted := bytes.Equal(framed[:8], []byte{123, 103, 133, 190, 34, 45, 76, 240})
	encryptedCompr := bytes.Equal(framed[:8], []byte{230, 89, 27, 191, 11, 191, 216, 11})
	if encrypted || encryptedCompr {
		if m.cryptKey == nil {
			return nil, true, fmt.Errorf("encrypted blob but the mock has no key")
		}
		if len(framed) < 44 {
			return nil, true, fmt.Errorf("encrypted frame too short: %d", len(framed))
		}
		iv, tag, ct := framed[12:28], framed[28:44], framed[44:]
		if crc := binary.LittleEndian.Uint32(framed[8:12]); crc != crc32.ChecksumIEEE(ct) {
			return nil, true, fmt.Errorf("crc mismatch")
		}
		block, err := aes.NewCipher(m.cryptKey[:])
		if err != nil {
			return nil, true, err
		}
		aead, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			return nil, true, err
		}
		sealed := append(append(make([]byte, 0, len(ct)+16), ct...), tag...)
		payload, err := aead.Open(nil, iv, sealed, nil)
		if err != nil {
			return nil, true, fmt.Errorf("gcm open: %v", err)
		}
		if encryptedCompr {
			payload, err = m.zdec.DecodeAll(payload, nil)
		}
		return payload, true, err
	}

	payload := framed[12:]
	if crc := binary.LittleEndian.Uint32(framed[8:12]); crc != crc32.ChecksumIEEE(payload) {
		return nil, false, fmt.Errorf("crc mismatch")
	}
	switch {
	case bytes.Equal(framed[:8], []byte{66, 171, 56, 7, 190, 131, 112, 161}):
		return payload, false, nil
	case bytes.Equal(framed[:8], []byte{49, 185, 88, 66, 111, 182, 163, 127}):
		payload, err := m.zdec.DecodeAll(payload, nil)
		return payload, false, err
	}
	return nil, false, fmt.Errorf("unknown blob magic %x", framed[:8])
}

// setCryptKey arms the mock's encrypted-upload verification, deriving the
// digest-namespace key independently of the client implementation.
func (m *mockPBS) setCryptKey(key [32]byte) {
	m.cryptKey = &key
	idKey, err := pbkdf2.Key(sha256.New, string(key[:]), []byte("_id_key"), 10, 32)
	if err != nil {
		m.t.Fatalf("mock id key: %v", err)
	}
	copy(m.idKey[:], idKey)
}

// makeDidx builds a synthetic dynamic index file for previous-backup tests.
func makeDidx(entries ...[32]byte) []byte {
	out := make([]byte, 4096, 4096+40*len(entries))
	copy(out, []byte{28, 145, 78, 165, 25, 186, 179, 205})
	offset := uint64(0)
	for _, d := range entries {
		offset += 1 << 20
		out = binary.LittleEndian.AppendUint64(out, offset)
		out = append(out, d[:]...)
	}
	return out
}
