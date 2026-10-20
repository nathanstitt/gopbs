package pbs_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/osshield/gopbs/pbs"
)

// TestEncryptedBlobRoundTrip covers both encrypted magics: compressible data
// keeps the compressed representation, incompressible data stays raw.
func TestEncryptedBlobRoundTrip(t *testing.T) {
	key := testKey(t)
	cfg := &pbs.CryptConfig{Key: key}
	enc := pbs.NewBlobEncoder()

	compressible := bytes.Repeat([]byte("gopbs encrypted blob "), 1024)
	incompressible := make([]byte, 4096)
	if _, err := rand.Read(incompressible); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		plain     []byte
		compress  bool
		wantMagic byte // first magic byte distinguishes the two
		wantSmall bool // framed smaller than plain+44
	}{
		{"compressed", compressible, true, 230, true},
		{"incompressible stays raw", incompressible, true, 123, false},
		{"compression disabled", compressible, false, 123, false},
		{"empty payload", nil, true, 123, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			framed, err := enc.EncodeEncrypted(tc.plain, tc.compress, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if framed[0] != tc.wantMagic {
				t.Fatalf("magic starts with %d, want %d", framed[0], tc.wantMagic)
			}
			if tc.wantSmall != (len(framed) < len(tc.plain)+44) {
				t.Fatalf("framed size %d for plain %d, wantSmall=%v", len(framed), len(tc.plain), tc.wantSmall)
			}
			got, err := pbs.DecryptBlob(framed, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.plain) {
				t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(tc.plain))
			}

			// Wrong key must fail authentication, not return garbage.
			bad := key
			bad[31] ^= 1
			if _, err := pbs.DecryptBlob(framed, bad); err == nil {
				t.Fatal("decrypt succeeded with wrong key")
			}

			// A flipped ciphertext bit must fail the CRC (and the seal).
			if len(framed) > 44 {
				corrupt := bytes.Clone(framed)
				corrupt[44] ^= 1
				if _, err := pbs.DecryptBlob(corrupt, key); err == nil {
					t.Fatal("decrypt succeeded on corrupted ciphertext")
				}
			}
		})
	}
}

// TestEncryptedBlobIVUniqueness: every frame gets a fresh random IV, and the
// scratch-buffer reuse across encodes on one encoder does not corrupt
// earlier output.
func TestEncryptedBlobIVUniqueness(t *testing.T) {
	key := testKey(t)
	cfg := &pbs.CryptConfig{Key: key}
	enc := pbs.NewBlobEncoder()
	plain := bytes.Repeat([]byte("same payload every time "), 256)

	seen := make(map[[16]byte]bool)
	var frames [][]byte
	for i := 0; i < 8; i++ {
		framed, err := enc.EncodeEncrypted(plain, true, cfg)
		if err != nil {
			t.Fatal(err)
		}
		var iv [16]byte
		copy(iv[:], framed[12:28])
		if seen[iv] {
			t.Fatal("IV reused")
		}
		seen[iv] = true
		frames = append(frames, framed)
	}
	// All frames must still decrypt after later encodes reused the scratch.
	for i, f := range frames {
		got, err := pbs.DecryptBlob(f, key)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("frame %d corrupted by later encode", i)
		}
	}
}
