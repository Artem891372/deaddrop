package crypto

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Identity is a participant's secret key material: a key-agreement keypair
// (encryption) and a signing keypair. Keys are generated and held only on the
// endpoint and never travel to the carrier (TR-S-10).
type Identity struct {
	SuiteID         byte
	EncPriv, EncPub []byte
	SigPriv, SigPub []byte
}

// Contact is the public "identity card" of a correspondent — what one shares to
// be reachable. Its fingerprint is verified out-of-band (TR-S-8).
type Contact struct {
	SuiteID        byte
	EncPub, SigPub []byte
}

// NewIdentity generates a fresh identity for the given suite.
func NewIdentity(s Suite) (*Identity, error) {
	encPriv, encPub, err := s.GenerateKEMKey()
	if err != nil {
		return nil, err
	}
	sigPriv, sigPub, err := s.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	return &Identity{
		SuiteID: s.ID(),
		EncPriv: encPriv, EncPub: encPub,
		SigPriv: sigPriv, SigPub: sigPub,
	}, nil
}

// Contact returns the public card for this identity.
func (id *Identity) Contact() Contact {
	return Contact{SuiteID: id.SuiteID, EncPub: id.EncPub, SigPub: id.SigPub}
}

// Suite resolves the identity's suite, or nil if its id is unknown.
func (id *Identity) Suite() Suite { return Lookup(id.SuiteID) }

var fpEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint returns a short, human-comparable identifier derived from the
// contact's suite and public keys, for out-of-band verification (defends T10,
// the man-in-the-middle on first key exchange). Equal fingerprints imply equal
// suite and public keys; participants compare them over a trusted side channel.
func (c Contact) Fingerprint() string {
	h := sha256.New()
	h.Write([]byte{c.SuiteID})
	h.Write(c.EncPub)
	h.Write(c.SigPub)
	sum := h.Sum(nil)[:10] // 80 bits → 16 base32 chars
	s := fpEnc.EncodeToString(sum)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}
