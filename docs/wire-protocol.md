# The PBS backup wire protocol

Reference for the network protocol the `pbs` package speaks, as implemented
against both a real Proxmox Backup Server and
[pmoxs3backuproxy](https://github.com/tizbac/pmoxs3backuproxy). The authority
is `proxmox-backup` (`src/api2/backup/`); differences between the two server
implementations gopbs accommodates are called out inline.

## 1. Transport and authentication

All traffic is HTTPS (default port 8007). Certificate trust is one of:

- **Fingerprint pinning** (recommended for self-signed servers): the SHA-256
  of the server certificate's DER encoding, colon-separated hex. When set it
  is enforced unconditionally and replaces chain verification — a lesson from
  the reference client, whose fingerprint check was dead code.
- Standard chain verification (no fingerprint configured).
- `InsecureSkipAll` for lab use.

Two authentication methods:

- **API token**: every request carries
  `Authorization: PBSAPIToken=<user@realm!tokenname>:<secret>`.
- **Ticket (username/password)**: `POST /api2/json/access/ticket` with
  `username=<user@realm>&password=...` returns `{data: {ticket, CSRFPreventionToken}}`.
  Subsequent requests carry `Cookie: PBSAuthCookie=<ticket>` plus
  `CSRFPreventionToken: <token>` on non-GET requests. Tickets are valid ~2
  hours; gopbs caches them and renews 15 minutes before expiry.

## 2. Session establishment (protocol upgrade)

A backup session is one long-lived connection speaking HTTP/2 after an
HTTP/1.1 upgrade handshake:

```
GET //api2/json/backup?backup-type=host&backup-id=myhost&backup-time=1755900000&store=datastore[&ns=namespace] HTTP/1.1
Upgrade: proxmox-backup-protocol-v1
Connection: Upgrade
<auth headers>
```

- The **double slash** (`//api2/json/backup`) mirrors the official client
  verbatim: the real server normalizes it, and pmoxs3backuproxy matches on
  exactly this prefix.
- `backup-time` is Unix seconds and fixes the snapshot identity for the whole
  session.
- The server answers `101 Switching Protocols`; from then on the same TCP
  connection carries HTTP/2 (h2c inside the TLS stream — the client starts an
  HTTP/2 client connection over the upgraded socket).

One session writes exactly one snapshot. gopbs binds the session to that
single HTTP/2 connection: if it drops, the session fails rather than silently
dialing a second connection mid-snapshot (a reference-client defect).

## 3. Endpoints inside the session

All paths below are relative (`/previous`, not `/api2/json/...`), sent over
the upgraded HTTP/2 connection. Responses are JSON (`{"data": ...}`) unless
noted.

### GET /previous?archive-name=NAME

Returns the raw `.didx` of the named archive from the previous snapshot of
the same backup type+id — the deduplication seed. "Nothing to seed from" is
reported inconsistently and all variants must be treated as the normal
first-backup case:

| Server | Response |
|---|---|
| real PBS, no previous snapshot | `400` "no valid previous backup" |
| real PBS, snapshot exists but lacks the archive (e.g. first v2 backup on an id with v1 history) | `400` "Unable to open dynamic index ... No such file or directory" |
| pmoxs3backuproxy | `404` |

As a side effect the real server registers the returned index's chunks as
*known* to the session, so appends may reference them without re-upload.
pmoxs3backuproxy resolves "previous" at whole-second granularity — two
snapshots within the same second do not see each other.

### POST /dynamic_index — create

Body **and** query string: `{"archive-name": "root.pxar.didx"}`. The real
server requires the JSON body and ignores the query; pmoxs3backuproxy parses
only the query. gopbs sends both. Returns the writer id (`wid`) used by all
subsequent calls for this index.

### POST /dynamic_chunk?wid=W&digest=HEX&size=RAW&encoded-size=N

Body: the **encoded blob** (§4) of one chunk. `size` is the raw chunk length,
`encoded-size` the blob length, `digest` the SHA-256 of the raw chunk
(lowercase hex). Chunks are content-addressed: uploading the same digest
twice is legal but wasteful — the client is expected to dedup.

### PUT /dynamic_index — append

Body: `{"wid": W, "digest-list": [...], "offset-list": [...]}` with at most
**128** entries per call. Offsets are the chunks' **start** positions in the
archive stream, and appends must arrive in strictly ascending contiguous
order. Every referenced digest must already be known (uploaded in this
session or registered via `/previous`).

### POST /dynamic_close?wid=W&chunk-count=N&size=S&csum=HEX

Finishes an index; like create, the parameters are sent both as query string
and JSON body (dual-encoded for the two server implementations). `csum` is
the **index checksum**: SHA-256 over, for each chunk in order, the
little-endian u64 **end offset** followed by the 32-byte digest. `size` is
the total stream length, `chunk-count` the number of index entries. The
server verifies all three.

### POST /blob?file-name=NAME&encoded-size=N

Body: an encoded blob (§4). Used for small whole files in the snapshot
(configs, logs, gopbs's metadata blobs); recorded in the manifest with the
size and SHA-256 of the **encoded** blob as stored — the restore path
verifies both against the stored file, so recording the raw payload size
breaks restores.

### POST /finish

Uploads nothing by itself in gopbs's flow: gopbs first uploads the manifest
(`index.json.blob`, §5) via `/blob`, then calls `/finish` to commit the
snapshot and closes the connection. An unfinished session that merely closes
its connection is discarded by the server.

## 4. Blob framing

Chunks and blobs share one container format:

```
u64  magic
u32  crc32 (IEEE) of everything after this 12-byte header
[payload]
```

Encrypted blobs (`Config.Crypt` in encrypt mode) extend the header to 44
bytes; the CRC then covers only the ciphertext:

```
u64      magic
u32      crc32 (IEEE) of the ciphertext
[16]byte AES-256-GCM IV (random per blob; PBS uses a 16-byte IV, not GCM's
         default 12)
[16]byte GCM tag
[ciphertext]  (AAD is empty)
```

| Magic (byte sequence) | Meaning |
|---|---|
| `42 ab 38 07 be 83 70 a1` | uncompressed |
| `31 b9 58 42 6f b6 a3 7f` | zstd-compressed |
| `7b 67 85 be 22 2d 4c f0` | encrypted |
| `e6 59 1b bf 0b bf d8 0b` | zstd-compressed, then encrypted |

The encoder compresses with zstd and keeps the smaller representation — the
decision is made before framing (and before encryption; the payload is
compressed first, then sealed). `/dynamic_chunk` parameters keep their
meaning under encryption: `size` is the plaintext length, `encoded-size` the
framed length, and `digest` becomes the keyed digest
`SHA256(plaintext ‖ id_key)` where
`id_key = PBKDF2-HMAC-SHA256(key, "_id_key", 10 iterations)` — the digest
namespace the official client uses, so deduplication works per key. The
server never verifies encrypted digests; it trusts the client.

## 5. Dynamic index (.didx) and manifest

A raw `.didx` file (as returned by `/previous`):

```
4096-byte header:
  8 bytes  magic  1c 91 4e a5 19 ba b3 cd
  ...      (uuid, ctime, index csum, padding)
40-byte records:
  u64      end offset (cumulative, strictly increasing)
  [32]byte chunk digest
```

The manifest is `index.json.blob` — a JSON document uploaded via `/blob`
before `/finish`:

```json
{
  "backup-type": "host",
  "backup-id": "myhost",
  "backup-time": 1755900000,
  "files": [
    {"filename": "root.pxar.didx", "csum": "<index csum hex>", "size": 123, "crypt-mode": "none"},
    {"filename": "catalog.pcat1.didx", ...}
  ],
  "signature": null,
  "unprotected": {}
}
```

`csum`/`size` for an index are the values passed to `/dynamic_close`; for a
blob, the sha256 and size of the encoded blob as stored. The manifest blob
itself is stored uncompressed, matching the reference clients.

With a key configured (`Config.Crypt`), each file entry carries its
crypt-mode (`encrypt` or `sign-only`; the manifest itself stays `none` — it
is never encrypted), and the manifest gains:

- `signature`: hex of `HMAC-SHA256(id_key, canonical_json)`, where the
  canonical form is the manifest without its `signature` and `unprotected`
  members — object keys sorted bytewise, no whitespace, serde_json string
  escaping (byte-identical to `proxmox_serde::to_canonical_json`);
- `unprotected["key-fingerprint"]`: colon-separated hex of
  `SHA256(SHA256("Proxmox Backup Encryption Key Fingerprint") ‖ id_key)` —
  deliberately outside the signed portion, matching upstream.

With a master public key configured, one extra blob precedes the manifest:
`rsa-encrypted.key.blob`, the unprotected KeyConfig JSON encrypted with the
master RSA key (PKCS#1 v1.5), framed as a plain uncompressed blob but listed
with crypt-mode `encrypt`.

## 6. Archive naming

| Content | Index name |
|---|---|
| pxar v1 archive | `<base>.pxar.didx` |
| catalog | `catalog.pcat1.didx` (fixed) |
| v2 metadata stream | `<base>.mpxar.didx` |
| v2 payload stream | `<base>.ppxar.didx` |

The official client resolves `<base>.pxar` against a manifest by falling back
to the split pair when the plain name is absent, so v2 snapshots restore with
the same archive name users type for v1. v1 snapshots include the catalog so
the PBS UI can browse them; v2 snapshots must not include one (the UI reads
the metadata stream).

### Reused chunks

With metadata change detection the generator hands the uploader a framed
payload stream (package `reuse`): data frames are chunked as usual, an
injection frame forces a chunk boundary and appends the listed previous
chunks to the index by digest (`PUT /dynamic_index`) without uploading them.
The server accepts them because `GET /previous` on the payload index has
registered them as known to the session; a digest it did not register fails
the upload.

## 7. The upload pipeline (client side)

How gopbs drives the endpoints (per index):

1. `GET /previous` → parse the didx, register all digests as known
   (`ErrNoPrevious` → empty seed).
2. `POST /dynamic_index` → `wid`.
3. Producer cuts the stream into content-defined chunks (buzhash, §
   [pxar-format](pxar-format.md)); `Workers` goroutines hash, dedup
   (session-wide single-flight: concurrent uploads of the same digest
   collapse into one), compress and `POST /dynamic_chunk`.
4. A collector reassembles completions into stream order, maintains the index
   checksum, and issues `PUT /dynamic_index` appends in ≤128-chunk batches.
5. `POST /dynamic_close` with the final checksum.

A v2 backup runs two of these pipelines concurrently over one session (the
generator couples the streams, so sequential consumption could deadlock);
the dedup set is shared, so chunks appearing in both streams upload once.
Then the manifest blob and `/finish`.

## 8. Reading snapshots

### Snapshot listing (regular API)

```
GET /api2/json/admin/datastore/STORE/snapshots?backup-type=host&backup-id=myhost[&ns=namespace]
```

A plain HTTPS request with the usual auth headers (no upgrade). The token
needs `Datastore.Audit` or `Datastore.Backup`. The response is
`{"data": [{backup-type, backup-id, backup-time, size, protected, files:
[{filename, size, crypt-mode}]}, ...]}` in no guaranteed order; gopbs sorts
newest first.

### Reader session

A reader session opens like a backup session, with a different protocol and
the snapshot time required:

```
GET //api2/json/reader?backup-type=host&backup-id=myhost&backup-time=1755900000&store=datastore&debug=0[&ns=namespace] HTTP/1.1
Upgrade: proxmox-backup-reader-protocol-v1
Connection: Upgrade
<auth headers>
```

Endpoints inside the session:

- `GET /download?file-name=NAME` — one file of the snapshot as stored:
  `index.json.blob`, any `.blob`, or a raw `.didx`. Downloading an index
  also allows the session to read that index's chunks.
- `GET /chunk?digest=HEX` — one framed chunk as stored (blob framing, §4).
  The real server refuses chunks of indexes the session did not download.

gopbs verifies everything it reads: the manifest signature and key
fingerprint when a key is configured; blob size and SHA-256 against the
manifest; the index checksum against the manifest before any chunk is
fetched; each chunk's size and digest (the keyed digest for an encrypted
index); and the total size at the end of the stream.
