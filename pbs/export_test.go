package pbs

import (
	"fmt"
	"time"
)

// Test-only exports: compiled only for tests, keeping internals reachable
// from the external pbs_test package without widening the public API.

type BackupManifest = backupManifest

// SetHTTP2Timeouts shortens the dead-connection detection for a test.
func SetHTTP2Timeouts(t interface{ Cleanup(func()) }, readIdle, ping time.Duration) {
	oldIdle, oldPing := readIdleTimeout, pingTimeout
	readIdleTimeout, pingTimeout = readIdle, ping
	t.Cleanup(func() { readIdleTimeout, pingTimeout = oldIdle, oldPing })
}

var CanonicalManifestJSON = canonicalManifestJSON

// CryptDigest returns the keyed chunk digest for data under c.
func CryptDigest(c *CryptConfig, data []byte) ([32]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return [32]byte{}, err
	}
	return cs.computeDigest(data), nil
}

// CryptSignature returns HMAC-SHA256(id_key, data) for the key in c.
func CryptSignature(c *CryptConfig, data []byte) ([32]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return [32]byte{}, err
	}
	return cs.authTag(data), nil
}

// CryptFingerprint returns the colon-hex key fingerprint for the key in c.
func CryptFingerprint(c *CryptConfig) (string, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return "", err
	}
	return cs.fingerprintHex(), nil
}

// WrapKeyConfig returns the RSA-wrapped key-config document for the key and
// master public key in c.
func WrapKeyConfig(c *CryptConfig, now time.Time) ([]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return nil, err
	}
	return wrapKeyConfig(cs, now)
}

// EncodeEncrypted frames plain as an encrypted blob for the key in c.
func (e *BlobEncoder) EncodeEncrypted(plain []byte, compress bool, c *CryptConfig) ([]byte, error) {
	cs, err := newCryptState(c)
	if err != nil {
		return nil, err
	}
	return e.encodeEncrypted(plain, compress, cs.aead)
}

// DecryptBlob refuses plain frames, so tests prove the payload was
// encrypted.
func DecryptBlob(framed []byte, key [32]byte) ([]byte, error) {
	var magic [8]byte
	copy(magic[:], framed)
	if magic != blobEncryptedMagic && magic != blobEncryptedComprMagic {
		return nil, fmt.Errorf("not an encrypted blob magic: %x", magic)
	}
	return DecodeBlob(framed, &CryptConfig{Key: key})
}
