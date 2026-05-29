// Package crypto is layer L2 of DeadDrop: identities and the cryptographic
// primitives that protect a message in transit through an untrusted carrier.
//
// Algorithms are hidden behind the Suite interface (crypto-agility, TR-C-1):
// the wire format carries a one-byte suite id, so a suite can be swapped — e.g.
// the default modern suite for a GOST suite — without changing the protocol or
// the envelope format. This layer provides the primitives (key agreement, AEAD,
// signatures) and the sealed-box construction; the envelope framing and the
// sign-then-encrypt / recipient-binding policy live in layer L1 (drop).
package crypto

// Suite is a named bundle of cryptographic primitives. An implementation must
// be deterministic in its sizes (key/nonce lengths) so the envelope's
// length-prefixed fields round-trip across peers sharing the same suite id.
//
// Key-agreement keys (KEM) and signing keys are separate keypairs, by design
// (TR-K-1): one for confidentiality (DH), one for authenticity (signatures).
type Suite interface {
	// ID is the one-byte identifier written into the envelope header.
	ID() byte

	// --- Key agreement (Diffie–Hellman over a fixed curve) ---

	// GenerateKEMKey returns a fresh key-agreement keypair. The same routine
	// produces both an identity's long-term encryption key and the per-message
	// ephemeral key.
	GenerateKEMKey() (priv, pub []byte, err error)
	// DH computes the shared secret between our private key and a peer's public
	// key.
	DH(priv, peerPub []byte) ([]byte, error)

	// --- KDF + AEAD ---

	// KDF derives an AEAD key (AEADKeySize bytes) from a shared secret and a
	// context/info string.
	KDF(shared, info []byte) []byte
	AEADKeySize() int
	NonceSize() int
	// Seal/Open are the authenticated cipher; aad is authenticated but not
	// encrypted. Open returns an error if authentication fails (e.g. the blob
	// is not addressed to this recipient under this key).
	Seal(key, nonce, plaintext, aad []byte) []byte
	Open(key, nonce, ciphertext, aad []byte) ([]byte, error)

	// --- Signatures ---

	GenerateSigningKey() (priv, pub []byte, err error)
	Sign(priv, msg []byte) []byte
	Verify(pub, msg, sig []byte) bool
}

// suites is the registry of known suites, keyed by id, used to resolve the
// suite named in an incoming envelope header.
var suites = map[byte]Suite{}

func register(s Suite) { suites[s.ID()] = s }

// Lookup returns the registered suite for id, or nil if unknown.
func Lookup(id byte) Suite { return suites[id] }
