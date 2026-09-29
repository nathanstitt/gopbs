// Package pbs is a Proxmox Backup Server client for creating and reading
// backups.
//
// It supports API-token and username/password (ticket) authentication,
// SHA-256 certificate fingerprint pinning, and the HTTP/2 backup protocol
// (proxmox-backup-protocol-v1): dynamic indexes, content-defined chunk upload
// with zstd compression and deduplication against the previous snapshot,
// blobs, manifest and finish. Chunk uploads run on a parallel pipeline while
// index order is preserved by sequence numbers.
//
// Client-side encryption (Config.Crypt) is compatible with
// proxmox-backup-client: AES-256-GCM chunks and blobs, keyed chunk digests
// so deduplication works per key, signed manifests, proxmox key.json files
// (LoadKeyFile/CreateKeyFile) and RSA master-key wrapping.
//
// ListSnapshots and StartReader (proxmox-backup-reader-protocol-v1) read
// snapshots back, verified and decrypted.
package pbs
