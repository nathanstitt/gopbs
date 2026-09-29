# gopbs

GoPBS is a pure-Go library for backing up data to [Proxmox Backup Server](https://www.proxmox.com/en/products/proxmox-backup-server/overview) (PBS).
It generates PXAR archives (v1 and the split v2 format) and `.pcat1` catalogs, chunks and
deduplicates content exactly like the official client, and uploads over the PBS HTTP/2
backup protocol — either as one `gopbs.Backup` call or through the individual building
blocks (`archive`, `pxar`, `catalog`, `chunker`, `scan`, `pbs`).

Output is validated byte-for-byte against the official `pxar` tool, and snapshots restore
with the stock `proxmox-backup-client`. Full Linux metadata fidelity: ownership, modes,
timestamps (ns), xattrs, POSIX ACLs, file capabilities, quota project IDs, hardlinks,
symlinks, device nodes, FIFOs and sockets.

## Credit
Credit where credit is due - I did not figure most of this process out by myself.

A large part of the initial work regarding finding the specification, optimizing the backup process, etc. was done by [@tizbac](https://github.com/tizbac), go support his work if you are able.

## Performance
We include performance tests (`cd tests && GOPBS_PERF=1 GOPBS_PERF_MB=512 go test -tags integration -run TestPerformance -v .`). The results are roughly as follows:


| Tooling | Format | Mode | Time | Throughput |
|---|---|---|---|---|
| gopbs | v1 | sync (workers=1) | 2.81s | 182.0 MiB/s |
| gopbs | v1 | async (workers=8) | **0.79s** | 649.9 MiB/s |
| gopbs | v2 | async | 0.76s | 676.9 MiB/s |
| official `pxar` cli | v1 | docker | 7.28s | 70.3 MiB/s |
| official `pxar` cli | v2 | docker | 4.22s | 121.5 MiB/s |
| gopbs | v1 | upload (fresh) | 3.72s | 137.6 MiB/s |
| gopbs | v1 | upload (dedup rerun) | 1.93s | 265.6 MiB/s |
| gopbs | v2 | upload (fresh) | 2.72s | 188.4 MiB/s |
| gopbs | v2 | upload (dedup rerun) | 1.82s | 281.5 MiB/s |
| official client | v1 | upload (fresh) | 3.03s | 168.9 MiB/s |
| official client | v1 | upload (dedup rerun) | 1.78s | 288.1 MiB/s |
| official client | v2 | upload (fresh) | 3.58s | 142.8 MiB/s |
| official client | v2 | upload (dedup rerun) | 0.79s | 651.9 MiB/s |


## Installation

```bash
go get github.com/osshield/gopbs
```

A small CLI for generating archives to files (used by the integration harness) ships as well:

```bash
go install github.com/osshield/gopbs/cmd/gopbs-pxar@latest
gopbs-pxar -catalog out.pcat1 out.pxar /some/dir                 # v1 + catalog
gopbs-pxar -payload out.ppxar out.mpxar /some/dir                # v2 split archive
```

## Quickstart: full backup

One call — scan, plan, generate, chunk, deduplicate against the previous snapshot,
upload, catalog, manifest, finish. Everything is streamed; nothing is written to disk.

```go
result, err := gopbs.Backup(context.Background(), gopbs.BackupOptions{
    Client: pbs.Config{
        BaseURL:     "https://pbs.example.com:8007",
        Auth:        pbs.TokenAuth{AuthID: "backup@pbs!mytoken", Secret: "…"},
        Fingerprint: "AA:BB:…", // sha256 fingerprint of the server certificate
        Datastore:   "backups",
    },
    Archive: archive.Options{
        Name: "root",
        Scan: scan.Options{
            SkipOnError: true,
            Exclude:     []string{"*.tmp", "!keep.tmp", "cache/"}, // proxmox-backup-client --exclude syntax
        },
    },
    Ref:   pbs.SnapshotRef{Type: "host", ID: "myhost"},
    Paths: []string{"/etc", "/srv"},
})
```

`PasswordAuth` (ticket login) works in place of `TokenAuth`. A single directory in
`Paths` becomes the archive root; multiple paths (and `Streams` — virtual files backed
by `io.Reader`s) are placed under a virtual root named after the archive. Set
`OnProgress` for live per-chunk progress, and read non-fatal events (skipped entries,
files that changed mid-read) from `result.Warnings`.

**Excluding entries.** `Scan.Exclude` takes patterns in the official client's
`--exclude` syntax: a leading `/` anchors to the archive root, a trailing `/` matches
directories only, `!` re-includes, `**` spans directory levels, and the last matching
pattern wins. They are recorded in the archive exactly as `proxmox-backup-client` does
(a `.pxarexclude-cli` file in the v1 root, the prelude record in v2). Set
`Scan.PxarExcludeFiles` to honour `.pxarexclude` files found in the tree, and
`Scan.Filter` for arbitrary logic (size, age, device boundaries) that leaves no trace
in the archive. See [docs/api.md](docs/api.md#excluding-entries).

Set `Format: gopbs.FormatV2` for split archives: metadata (`.mpxar`) and payload
(`.ppxar`) upload as two concurrent indexes, so metadata-only changes (touched mtimes,
permissions) leave the payload stream — by far the larger one — fully deduplicated.
Restore requires `proxmox-backup-client` ≥ 3.2; v1 is the safe default for older
servers and [pmoxs3backuproxy](https://github.com/tizbac/pmoxs3backuproxy).

## Quickstart: archive only

The `archive` package generates PXAR streams without any server involved:

```go
a, _ := archive.New(archive.Options{})
_ = a.AddDirectory("/etc")

stream, _ := a.GenerateV1(context.Background())
defer stream.Close()

out, _ := os.Create("/tmp/etc.pxar")
defer out.Close()
io.Copy(out, stream)
```

`GenerateCatalog` produces the matching `.pcat1`, `GenerateV2` the split stream pair
(consume both concurrently), and `EstimatedSizeV1`/`EstimatedSizeV2` exact size
estimates from scan metadata. Generation is asynchronous by default — a worker pool
reads file contents in parallel and a reorder buffer keeps the output byte-identical
to synchronous mode (`Workers: 1`). Payload sizes are bound late (open+fstat at
dispatch), so files that change size between scan and read never corrupt the archive:
content is padded/truncated to the committed size and reported as a warning.

Runnable programs for all of this live in [examples/](examples/): sync, async,
multi-stream and v2 backups, each with a live progress bar.

## Feature Status
- [x] PXAR Archive generation
  - [x] PXAR Version 1
  - [x] PXAR Version 2 (split `.mpxar`/`.ppxar`, byte-identical to `pxar create --payload-output`)
  - [x] PCAT generation
  - [x] Synchronous and asynchronous archive generation
  - [x] Compression (zstd, per chunk — as PBS stores data)
  - [x] Encryption (AES-256-GCM, key-file compatible with `proxmox-backup-client`, signed manifests, sign-only mode, RSA master-key wrapping)
  - [x] Exclusions (`--exclude` pattern syntax of `proxmox-backup-client`, `.pxarexclude` files, custom filter callback; recorded in the archive like the official client, byte-identical output)

- [x] Backup to PBS and [@tizbac/pmoxs3backuproxy](https://github.com/tizbac/pmoxs3backuproxy) (S3-compatible proxy for PBS)
  - [x] Directories (single or multiple)
  - [x] Files (single file or multiple files per archive)
  - [x] Data stream (stdin, readers)*
  - [x] Synchronous and parallel backup uploads
  - [x] Deduplication and change-only uploads

* **Streams are implemented, but if the size of the stream changes (increases) after the backup operation has started for that stream, there will be a loss of data. Always make sure the stream doesn't get any more data after backups have begun.**

- [ ] Restore data from PBS
  - [x] List snapshots
  - [x] Read blobs and raw dynamic indexes (verified and decrypted)
  - [ ] Restore to disk (no pxar decoder)
  - [x] Restore to stream (`io.Reader`)
  - [x] Synchronous and parallel restore

- [ ] Backup and restore sources
  - [x] Linux filesystem
    - [x] Plain Filesystem (ext4, xfs, btrfs, etc.)
    - [ ] Snapshot-based (LVM, ZFS, BTRFS, etc.)
    - [ ] Remote filesystems (via rclone)
    - [ ] Block devices

  - [ ] Windows filesystem
    - [ ] Plain Filesystem (NTFS, FAT32, exFAT, etc.)
    - [ ] Snapshot-based (VSS)

  - [ ] Backup and restore databases
    - [ ] MySQL
    - [ ] PostgreSQL
    - [ ] MongoDB
    - [ ] SQL Server

  - [ ] Backup and restore kubernetes
    - [ ] Backup PVCs (non-snapshot)
    - [ ] Backup snapshots (via CSI and Snapshot API)
    - [ ] Backup cluster resources/state

## Documentation

- [docs/api.md](docs/api.md) — API guide: how the packages fit together, the
  one-call path, archive-only use, the client on its own, concurrency notes.
- [docs/pxar-format.md](docs/pxar-format.md) — the PXAR v1/v2 formats and the
  `.pcat1` catalog, byte for byte.
- [docs/wire-protocol.md](docs/wire-protocol.md) — the PBS backup wire
  protocol: auth, upgrade handshake, endpoints, blob framing, didx, manifest,
  and the reader protocol.
- [docs/integration-harness.md](docs/integration-harness.md) — the docker
  test stack, what each test proves, the performance comparison.
- [ARCHITECTURE.md](ARCHITECTURE.md) — design rationale;
  [IMPLEMENTATION.md](IMPLEMENTATION.md) — phase-by-phase build-out with
  verification notes.

The integration harness in [tests/](tests/) byte-compares gopbs output against the
official `pxar` CLI and tizbac's client, restores snapshots with the official
`proxmox-backup-client` from a pmoxs3backuproxy+garage stack, and verifies full
end-to-end backups including second-run deduplication:

```bash
cd tests && go test -tags integration .
```

<details>
<summary><b>Fully annotated example (all options)</b></summary>

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/scan"
)

func main() {
	started := time.Now()

	result, err := gopbs.Backup(context.Background(), gopbs.BackupOptions{
		Client: pbs.Config{
			// The URL of the PBS instance, including https and port
			BaseURL: "https://my-pbs.instance.localhost:8007",

			// Authenticate with AuthID and Secret (token-based)
			Auth: pbs.TokenAuth{
				AuthID: "root@pbs!token",
				Secret: "12345678-1234-1234-1234-1234567890ab",
			},

			// You can also authenticate with username/password
			// Auth: pbs.PasswordAuth{
			//     Username: "root",
			//     Realm: "pbs",
			//     Password: "my-secure-password"
			// },

			// The datastore to use for the backup
			Datastore: "SRV-TESTS",

			// Optionally, you can specify a different namespace
			// Namespace:       "my-namespace",

			// The fingerprint of the PBS server's TLS certificate (SHA256)
			Fingerprint: "2F:6B:30:B8:B4:8B:5C:95:40:B9:F0:06:4B:5F:62:6A:47:E9:8B:27:EE:09:96:0C:30:F1:22:AE:58:B9:A5:24",

			// Alternatively, you can skip TLS verification (not recommended for production)
			// InsecureSkipAll: true,

			// Number of concurrent workers for uploading chunks to PBS.
			// Default: 4
			Workers: 6,

			// Set the average chunk size, must be a power of two
			// Generally, this does not need to be changed, but can be adjusted for performance tuning
			// in some specific scenarios. The default value is 4MiB, which balances speed and efficiency for deduplication.
			// Default: 4MiB
			// ChunkSizeAvg: 4 * 1024 * 1024,

			// If you want to follow the upload progress, you can use the OnProgress callback.
			// OnUploadProgress: func(archiveName string, stats pbs.UploadStats, done bool) {}
		},

		Archive: archive.Options{
			// The archive ID (name)
			Name: "my-archive-name",

			// Number of concurrent workers for reading file contents.
			// 0 = GOMAXPROCS, 1 = fully synchronous generation.
			Workers: 5,

			// Settings for scanning and creating the archive
			Scan: scan.Options{
				// Skip files on error instead of failing the entire backup
				SkipOnError: true,

				// Replaces the metadata reader with a custom implementation instead of the linux stat reader.
				// This is useful for testing environments or to add metadata to a stream-based backup
				// Reader: scan.MetadataReader(nil),

				// If true, skip reading quota project IDs from the filesystem
				// This can improve performance, and saves one ioctl call per directory and file,
				// but it means that the backup will not be able to restore quota project IDs.
				// SkipQuotaProjIDs: false,

				// Exclude patterns in proxmox-backup-client --exclude syntax, matched against
				// archive-relative paths; last match wins. Recorded in the archive like the
				// official client does (.pxarexclude-cli in v1, the prelude in v2).
				Exclude: []string{"*.tmp", "!keep.tmp", "cache/", "/var/cache", "**/node_modules"},

				// Honour .pxarexclude files found in the scanned directories (off by default).
				// PxarExcludeFiles: true,

				// Arbitrary exclusion logic; return false to omit the entry and its subtree.
				// Not recorded in the archive.
				// Filter: func(path, archivePath string, st scan.Stat) bool { return st.Size < 1<<30 },

				// Called for every entry left out by Exclude, .pxarexclude or Filter.
				// OnExclude: func(path, archivePath string) { log.Println("excluded", path) },
			},

			// This function is called for each warning encountered during archive generation.
			// Warnings are also collected into result.Warnings.
			OnWarn: func(w archive.Warning) {
				fmt.Fprintf(os.Stderr, "warning: %s (kind %d, err %v)\n", w.Path, w.Kind, w.Err)
			},

			// The memory budget for the async reorder buffer.
			// Default: 64MiB
			// Buffer: 64 * 1024 * 1024,
		},
		Ref: pbs.SnapshotRef{
			// Set the snapshot/backup type. Valid values are "host", "vm", or "ct". Default is "host".
			Type: "ct",

			// Set the ID for the snapshot. If empty, it defaults to the hostname of the machine running the backup.
			ID: "my-container-name",

			// Manually set the timestamp for the backup snapshot.
			// Default: time.Now()
			// Time: time.Now(),
		},

		// Set the archive format for uploads.
		// FormatV1 is the classic single-stream pxar plus a .pcat1 catalog, supported everywhere.
		// FormatV2 is the split .mpxar/.ppxar format: better deduplication for metadata-only
		// changes, requires proxmox-backup-client >= 3.2 to restore.
		Format: gopbs.FormatV1,

		// Filesystem paths to include in the backup.
		// If more than one is selected, a virtual top-level directory will be created with the name of the archive.
		// If a single directory is selected, it will become the root of the archive.
		Paths: []string{"/srv", "/var"},

		// Virtual files backed by readers, placed alongside Paths under the virtual root.
		// Streams: []gopbs.Stream{{Name: "dump.sql", Size: size, Reader: r}},

		// Metadata blobs stored in the snapshot alongside the archive (not part of it) —
		// for backup metadata PBS has no native place for. Restored with
		// `proxmox-backup-client restore <snapshot> app-meta.json.blob <target>`.
		// Blobs: []gopbs.Blob{{Name: "app-meta.json", Data: metaJSON}},

		// Callback for live progress updates during the backup process.
		// OnProgress: func(p gopbs.Progress) {},

		// Skip the PCAT catalogue upload. This means the snapshot will not be browsable in the PBS UI.
		// FormatV1 only; v2 has no catalog.
		// SkipCatalog: false,
	})
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("backed up %s/%s/%s: %d bytes in %d chunks (%d uploaded, %d deduplicated), catalog %d bytes, %d warnings (%.1fs)\n",
		result.Ref.Type, result.Ref.ID, result.Ref.Time.UTC().Format(time.RFC3339),
		result.Archive.Size, result.Archive.ChunkCount,
		result.Archive.NewChunks, result.Archive.ReusedChunks,
		result.Catalog.Size, len(result.Warnings), time.Since(started).Seconds())
}
```

</details>

## License

See [LICENSE](LICENSE).
