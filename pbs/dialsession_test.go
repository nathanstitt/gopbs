package pbs_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/osshield/gopbs/internal/pbsmock"
	"github.com/osshield/gopbs/pbs"
)

// upgradedConn preserves bytes the bufio.Reader consumed past the 101.
type upgradedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *upgradedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// proxyDial plays the role of a proxy: it performs the upgrade against the
// mock server with its own credentials and hands back the raw connection.
func proxyDial(m *pbsmock.Server) func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error) {
	return func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error) {
		conn, err := tls.Dial("tcp", strings.TrimPrefix(m.BaseURL, "https://"), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(conn, "GET //api2/json/backup?backup-id=%s&backup-time=%d&backup-type=%s&store=store1 HTTP/1.1\r\n"+
			"Host: proxy\r\nAuthorization: PBSAPIToken=proxy@pam!token:s3cret\r\n"+
			"Upgrade: proxmox-backup-protocol-v1\r\nConnection: Upgrade\r\n\r\n",
			ref.ID, ref.Time.Unix(), ref.Type)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			conn.Close()
			return nil, fmt.Errorf("upgrade refused: %s", resp.Status)
		}
		return &upgradedConn{Conn: conn, r: br}, nil
	}
}

func TestDialSession(t *testing.T) {
	m := pbsmock.New(t)
	ctx := context.Background()

	// No BaseURL, Auth or Datastore: the dialer owns the connection.
	c, err := pbs.NewClient(pbs.Config{DialSession: proxyDial(m)})
	if err != nil {
		t.Fatalf("NewClient with DialSession: %v", err)
	}

	s, err := c.StartBackup(ctx, pbs.SnapshotRef{ID: "tunnelhost"})
	if err != nil {
		t.Fatalf("StartBackup: %v", err)
	}
	defer s.Abort()
	if got := s.Ref(); got.ID != "tunnelhost" || got.Type != "host" {
		t.Errorf("session ref = %+v", got)
	}

	wid, err := s.CreateDynamicIndex(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatalf("CreateDynamicIndex: %v", err)
	}
	plain := []byte("hello through the tunnel")
	digest := sha256.Sum256(plain)
	if err := s.UploadDynamicChunk(ctx, pbs.NewBlobEncoder(), wid, digest, plain); err != nil {
		t.Fatalf("UploadDynamicChunk: %v", err)
	}
	if err := s.AppendDynamicIndex(ctx, wid, []string{hex.EncodeToString(digest[:])}, []uint64{0}); err != nil {
		t.Fatalf("AppendDynamicIndex: %v", err)
	}
	if err := s.CloseDynamicIndex(ctx, wid, [32]byte{}, uint64(len(plain)), 1); err != nil {
		t.Fatalf("CloseDynamicIndex: %v", err)
	}
	if err := s.Finish(ctx); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	m.Mu.Lock()
	defer m.Mu.Unlock()
	if !m.Finished {
		t.Error("mock did not see /finish")
	}
	if len(m.UpgradeReqs) != 1 {
		t.Fatalf("expected one upgrade request, got %d", len(m.UpgradeReqs))
	}
	req := m.UpgradeReqs[0]
	if req.Header.Get("Authorization") != "PBSAPIToken=proxy@pam!token:s3cret" {
		t.Errorf("proxy credentials not used: %q", req.Header.Get("Authorization"))
	}
	if req.URL.Query().Get("backup-id") != "tunnelhost" || req.URL.Query().Get("store") != "store1" {
		t.Errorf("unexpected upgrade query %q", req.URL.RawQuery)
	}
	if _, ok := m.Blobs["index.json.blob"]; !ok {
		t.Error("manifest was not uploaded")
	}
}

func TestNewClientRequiresAuthWithoutDialSession(t *testing.T) {
	if _, err := pbs.NewClient(pbs.Config{BaseURL: "https://pbs.example:8007", Datastore: "s"}); err == nil {
		t.Error("expected an error without Auth or DialSession")
	}
	if _, err := pbs.NewClient(pbs.Config{DialSession: func(context.Context, pbs.SnapshotRef) (net.Conn, error) { return nil, nil }}); err != nil {
		t.Errorf("DialSession alone should be enough: %v", err)
	}
}
