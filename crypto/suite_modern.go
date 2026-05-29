package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// SuiteModernID is the id of the default suite written into the envelope header.
const SuiteModernID byte = 0x01

// modernSuite is the default cryptographic suite:
//
//	key agreement : X25519
//	KDF           : HKDF-SHA-256
//	AEAD          : XChaCha20-Poly1305
//	signatures    : Ed25519
//
// All primitives come from the standard library or golang.org/x/crypto, are
// well-vetted and constant-time, and need no configuration (TR-C-2).
type modernSuite struct{}

func init() { register(modernSuite{}) }

// Modern returns the default suite.
func Modern() Suite { return modernSuite{} }

func (modernSuite) ID() byte { return SuiteModernID }

func (modernSuite) GenerateKEMKey() (priv, pub []byte, err error) {
	priv = make([]byte, curve25519.ScalarSize)
	if _, err = io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func (modernSuite) DH(priv, peerPub []byte) ([]byte, error) {
	return curve25519.X25519(priv, peerPub)
}

func (modernSuite) KDF(shared, info []byte) []byte {
	r := hkdf.New(sha256.New, shared, nil, info)
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(r, key)
	return key
}

func (modernSuite) AEADKeySize() int { return chacha20poly1305.KeySize }
func (modernSuite) NonceSize() int   { return chacha20poly1305.NonceSizeX }

func (modernSuite) Seal(key, nonce, plaintext, aad []byte) []byte {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		// key always comes from KDF at the correct size; a mismatch is a bug.
		panic("deaddrop/crypto: invalid AEAD key size")
	}
	return aead.Seal(nil, nonce, plaintext, aad)
}

func (modernSuite) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func (modernSuite) GenerateSigningKey() (priv, pub []byte, err error) {
	pubk, privk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privk, pubk, nil
}

func (modernSuite) Sign(priv, msg []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(priv), msg)
}

func (modernSuite) Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
