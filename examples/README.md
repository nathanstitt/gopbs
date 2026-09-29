# Examples

Complete backups with a single `gopbs.Backup` call: scan -> plan -> generate ->
chunk -> deduplicate -> upload -> catalog -> manifest -> finish, fully streamed.

| Example | What it shows |
|---|---|
| [backup-sync](backup-sync/) | Fully synchronous generation (`Archive.Workers: 1`); `-exclude` (repeatable, `proxmox-backup-client --exclude` syntax) and `-pxarexclude` show exclusions. |
| [backup-async](backup-async/) | Asynchronous generation (the default): parallel payload reads reassembled in order — byte-identical output, much faster on many-file trees. |
| [backup-streams](backup-streams/) | Multiple streams of data — virtual files that exist nowhere on disk — under a virtual root: buffered generated content, file-backed streams, and pure readers of pre-known size. |
| [backup-v2](backup-v2/) | v2 split archives (`Format: gopbs.FormatV2`): metadata and payload streams uploaded concurrently as two indexes — metadata-only changes leave the payload stream fully deduplicated. Restore needs proxmox-backup-client ≥ 3.2. |
| [restore-stream](restore-stream/) | Reading back: `ListSnapshots`, a reader session on the newest snapshot, and one dynamic index (e.g. an `UploadStream` database file) copied out as a verified byte stream. |

All of them default to the docker test stack from
[tests/compose.yml](../tests/compose.yml) (the directory-based ones back up
`/tmp`):

```sh
cd tests && docker compose up -d garage pmoxs3 && cd ..
go run ./examples/backup-sync
go run ./examples/backup-sync -exclude '*.log' -exclude 'cache/' -pxarexclude
go run ./examples/backup-async     # run twice (a couple of seconds apart) to see dedup at work
go run ./examples/backup-v2        # split mpxar/ppxar upload
go run ./examples/restore-stream -id "$(hostname)" -archive root.pxar -out /tmp/root.pxar
```

Point them at a real server with `-url`, `-username`, `-realm`, `-password`,
`-fingerprint`, `-datastore`, `-source` and `-id`. For the lower-level
building blocks (sessions, manual chunk uploads, custom dedup) see the
`pbs` package documentation and `tests/pbs_test.go`.
