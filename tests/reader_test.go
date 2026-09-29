//go:build integration

package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osshield/gopbs/pbs"
)

// The official client restores the same stream, to prove both read the same
// bytes.
func TestReaderRoundTrip(t *testing.T) {
	startPBSStack(t)

	key, err := pbs.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := pbs.CreateKeyFile(key, nil, pbs.KDFNone, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "reader-key.json"), keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		crypt   *pbs.CryptConfig
		keyfile string
	}{
		{"plain", nil, ""},
		{"encrypted", &pbs.CryptConfig{Mode: pbs.CryptModeEncrypt, Key: key}, "/keys/reader-key.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			client, err := pbs.NewClient(pbs.Config{
				BaseURL:      pmoxURL,
				Auth:         pbs.PasswordAuth{Username: pmoxUser, Realm: pmoxRealm, Password: pmoxSecret},
				Fingerprint:  pmoxFingerprint,
				Datastore:    pmoxDatastore,
				Workers:      4,
				ChunkSizeAvg: 128 << 10,
				Crypt:        tc.crypt,
			})
			if err != nil {
				t.Fatal(err)
			}

			data := make([]byte, 3<<20)
			rand.Read(data)
			data = append(data, bytes.Repeat([]byte("sqlite page "), 100_000)...)
			blob := []byte(`{"app":"gopbs-harness","reader":true}`)

			id := fmt.Sprintf("gopbs-reader-%s-%d", tc.name, time.Now().UnixNano())
			sess := startSession(t, client, pbs.SnapshotRef{Type: "host", ID: id})
			defer sess.Abort()
			stats, err := sess.UploadStream(ctx, "data.db", bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if stats.Size != uint64(len(data)) || stats.NewBytes != stats.Size {
				t.Fatalf("upload stats: %+v", stats)
			}
			if err := sess.UploadBlob(ctx, pbs.NewBlobEncoder(), "manifest.blob", blob, true); err != nil {
				t.Fatal(err)
			}
			if err := sess.Finish(ctx); err != nil {
				t.Fatal(err)
			}
			ref := sess.Ref()

			snaps, err := client.ListSnapshots(ctx, "host", id)
			if err != nil {
				t.Fatal(err)
			}
			if len(snaps) != 1 || snaps[0].Ref.Time.Unix() != ref.Time.Unix() {
				t.Fatalf("listing = %+v, want the one snapshot at %v", snaps, ref.Time)
			}

			r, err := client.StartReader(ctx, snaps[0].Ref)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			gotBlob, err := r.DownloadBlob(ctx, "manifest.blob")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotBlob, blob) {
				t.Fatalf("blob = %q", gotBlob)
			}
			rc, err := r.OpenDynamicIndex(ctx, "data.db")
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("reader returned %d bytes, want %d (content differs)", len(got), len(data))
			}

			target := "reader-" + tc.name + ".db"
			snapshot := fmt.Sprintf("%s/%s/%s", ref.Type, ref.ID, ref.Time.UTC().Format(time.RFC3339))
			args := []string{"run", "--rm", "--remove-orphans",
				"-e", "SNAPSHOT=" + snapshot,
				"-e", "ARCHIVE=data.db.didx", // the official client needs the full name for a non-pxar index
				"-e", "TARGET=/restore/" + target,
				"-e", "RAW=1",
			}
			if tc.keyfile != "" {
				args = append(args, "-e", "KEYFILE="+tc.keyfile)
			}
			if err := compose(append(args, "pbsrestore")...); err != nil {
				t.Fatalf("restore: %v", err)
			}
			official, err := os.ReadFile(filepath.Join(restoreDir, target))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(official, data) {
				t.Fatalf("official client restored %d bytes, want %d (content differs)", len(official), len(data))
			}
		})
	}
}
