// Command restore-stream copies one dynamic index of a backup group's newest
// snapshot to a file.
//
// The flag defaults match the test stack in tests/compose.yml:
//
//	cd tests && docker compose up -d garage pmoxs3
//	go run ./examples/restore-stream -id myhost -archive root.pxar -out /tmp/root.pxar
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/osshield/gopbs/pbs"
)

func main() {
	var (
		url         = flag.String("url", "https://localhost:8007", "PBS base URL")
		username    = flag.String("username", "garagegarage", "user name (without realm)")
		realm       = flag.String("realm", "pbs", "authentication realm")
		password    = flag.String("password", "garagegaragegarage", "password")
		fingerprint = flag.String("fingerprint", "55:BC:29:4B:BA:B6:A1:03:42:A9:D8:51:14:9D:BD:00:D2:2A:9C:A1:B8:4A:85:E1:AF:B2:0C:48:40:D6:CC:A4", "server certificate SHA-256 fingerprint")
		datastore   = flag.String("datastore", "pbs", "datastore name")
		backupID    = flag.String("id", "", "backup id (required)")
		archiveName = flag.String("archive", "", "dynamic index to read, e.g. data.db (required)")
		outPath     = flag.String("out", "-", "output file; - for stdout")
	)
	flag.Parse()
	if *backupID == "" || *archiveName == "" {
		flag.Usage()
		os.Exit(2)
	}

	client, err := pbs.NewClient(pbs.Config{
		BaseURL:     *url,
		Auth:        pbs.PasswordAuth{Username: *username, Realm: *realm, Password: *password},
		Fingerprint: *fingerprint,
		Datastore:   *datastore,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	snaps, err := client.ListSnapshots(ctx, "host", *backupID)
	if err != nil {
		log.Fatal(err)
	}
	if len(snaps) == 0 {
		log.Fatalf("no snapshots for host/%s", *backupID)
	}
	ref := snaps[0].Ref
	fmt.Fprintf(os.Stderr, "reading %s from %s/%s/%s\n", *archiveName, ref.Type, ref.ID,
		ref.Time.UTC().Format(time.RFC3339))

	r, err := client.StartReader(ctx, ref)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	rc, err := r.OpenDynamicIndex(ctx, *archiveName)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()

	out := os.Stdout
	if *outPath != "-" {
		if out, err = os.Create(*outPath); err != nil {
			log.Fatal(err)
		}
	}
	n, err := io.Copy(out, rc)
	if err != nil {
		log.Fatal(err)
	}
	if err := out.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "%d bytes restored and verified\n", n)
}
