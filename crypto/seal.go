package crypto

import (
	"crypto/rand"
	"io"
)

const sealInfo = "deaddrop/seal/v1"

// Sealed is the output of SealTo: the ephemeral public key and nonce the
// recipient needs, plus the AEAD ciphertext. These map directly onto the
// envelope header fields filled in by layer L1.
type Sealed struct {
	EphPub     []byte
	Nonce      []byte
	Ciphertext []byte
}

// SealTo encrypts plaintext to a recipient's key-agreement public key using a
// fresh ephemeral key (the sealed-box construction). It provides forward
// secrecy on the sender side: the ephemeral private key is discarded here, so a
// later compromise of the sender reveals nothing (DR-4). The residual risk
// (T11) is compromise of the recipient's long-term key. aad is authenticated
// but not encrypted.
func SealTo(s Suite, recipientEncPub, plaintext, aad []byte) (*Sealed, error) {
	ephPriv, ephPub, err := s.GenerateKEMKey()
	if err != nil {
		return nil, err
	}
	shared, err := s.DH(ephPriv, recipientEncPub)
	zero(ephPriv)
	if err != nil {
		return nil, err
	}
	key := s.KDF(shared, []byte(sealInfo))
	zero(shared)
	nonce := make([]byte, s.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		zero(key)
		return nil, err
	}
	ct := s.Seal(key, nonce, plaintext, aad)
	zero(key)
	return &Sealed{EphPub: ephPub, Nonce: nonce, Ciphertext: ct}, nil
}

// OpenFrom reverses SealTo with the recipient's key-agreement private key. Any
// failure (wrong recipient, tampered blob or aad) is an error; callers treat
// "could not open" as "not addressed to me".
func OpenFrom(s Suite, recipientEncPriv, ephPub, nonce, ciphertext, aad []byte) ([]byte, error) {
	shared, err := s.DH(recipientEncPriv, ephPub)
	if err != nil {
		return nil, err
	}
	key := s.KDF(shared, []byte(sealInfo))
	zero(shared)
	pt, err := s.Open(key, nonce, ciphertext, aad)
	zero(key)
	return pt, err
}

// zero overwrites a secret buffer.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
