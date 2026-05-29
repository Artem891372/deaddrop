// Package drop is layer L1 of DeadDrop: the envelope format and the mailbox
// protocol over an untrusted carrier.
//
// An envelope is a single carrier blob with a random name. Its body is
// sign-then-encrypt: the sender signs a context that binds the recipient's
// public key (anti-forwarding, T8), then the whole inner record — including the
// signature and the sender's public key — is sealed to the recipient
// (sealed-box, L2). The carrier therefore learns neither the content nor the
// sender's identity (T1, T2, T6), and a captured envelope cannot be re-aimed at
// a different recipient.
package drop

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"deaddrop/crypto"
)

var magic = [4]byte{'D', 'D', 'E', '1'}

const (
	envVersion   byte = 0x01
	innerVersion byte = 0x01
	sigDomain         = "deaddrop/sig/v1"

	headerFixed = 6 // magic(4) + version(1) + suite_id(1); this prefix is the AEAD aad
)

var (
	errFormat = errors.New("drop: malformed envelope")
	errSig    = errors.New("drop: signature verification failed")
)

// opened is the decoded, verified content of an envelope.
type opened struct {
	senderSigPub []byte
	msgID        [16]byte
	convID       [16]byte
	seq          uint64
	timestamp    int64
	typ          string
	payload      []byte
}

// sigContext is the exact byte string the sender signs. It binds the recipient
// (recipientEncPub) so a signed payload cannot be replayed to a different
// recipient, plus the message identity and content.
func sigContext(suiteID byte, recipientEncPub []byte, msgID, convID [16]byte, seq uint64, typ string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString(sigDomain)
	b.WriteByte(suiteID)
	b.Write(recipientEncPub)
	b.Write(msgID[:])
	b.Write(convID[:])
	writeU64(&b, seq)
	_ = writeU8(&b, []byte(typ))
	writeU32(&b, payload)
	return b.Bytes()
}

// encodeInner serialises the (to-be-encrypted) inner record.
func encodeInner(senderSigPub []byte, ts int64, msgID, convID [16]byte, seq uint64, typ string, payload, sig []byte) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte(innerVersion)
	if err := writeU8(&b, senderSigPub); err != nil {
		return nil, err
	}
	writeU64(&b, uint64(ts))
	b.Write(msgID[:])
	b.Write(convID[:])
	writeU64(&b, seq)
	if err := writeU8(&b, []byte(typ)); err != nil {
		return nil, err
	}
	writeU32(&b, payload)
	if err := writeU8(&b, sig); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func decodeInner(b []byte) (*opened, []byte, error) {
	r := &reader{b: b}
	if r.u8() != innerVersion {
		return nil, nil, errFormat
	}
	o := &opened{}
	o.senderSigPub = r.lenU8()
	o.timestamp = int64(r.u64())
	copy(o.msgID[:], r.fixed(16))
	copy(o.convID[:], r.fixed(16))
	o.seq = r.u64()
	o.typ = string(r.lenU8())
	o.payload = append([]byte(nil), r.lenU32()...)
	sig := append([]byte(nil), r.lenU8()...)
	if r.err != nil {
		return nil, nil, r.err
	}
	return o, sig, nil
}

// sealBytes wraps an already-serialised inner record into the on-carrier
// envelope: a cleartext header (the AEAD aad) followed by the ephemeral key,
// nonce and ciphertext.
func sealBytes(s crypto.Suite, recipientEncPub, inner []byte) ([]byte, error) {
	var hdr bytes.Buffer
	hdr.Write(magic[:])
	hdr.WriteByte(envVersion)
	hdr.WriteByte(s.ID())
	aad := hdr.Bytes() // headerFixed bytes; authenticated, not encrypted

	sealed, err := crypto.SealTo(s, recipientEncPub, inner, aad)
	if err != nil {
		return nil, err
	}
	if err := writeU8(&hdr, sealed.EphPub); err != nil {
		return nil, err
	}
	if err := writeU8(&hdr, sealed.Nonce); err != nil {
		return nil, err
	}
	writeU32(&hdr, sealed.Ciphertext)
	return hdr.Bytes(), nil
}

// sealEnvelope builds a complete envelope from sender to recipient.
func sealEnvelope(sender *crypto.Identity, to crypto.Contact, msgID, convID [16]byte, seq uint64, ts int64, typ string, payload []byte) ([]byte, error) {
	if sender.SuiteID != to.SuiteID {
		return nil, fmt.Errorf("drop: suite mismatch sender=%d recipient=%d", sender.SuiteID, to.SuiteID)
	}
	s := crypto.Lookup(sender.SuiteID)
	if s == nil {
		return nil, fmt.Errorf("drop: unknown suite %d", sender.SuiteID)
	}
	sig := s.Sign(sender.SigPriv, sigContext(s.ID(), to.EncPub, msgID, convID, seq, typ, payload))
	inner, err := encodeInner(sender.SigPub, ts, msgID, convID, seq, typ, payload, sig)
	if err != nil {
		return nil, err
	}
	return sealBytes(s, to.EncPub, inner)
}

// openEnvelope attempts to decrypt and verify raw with the recipient identity.
// It returns (nil, nil) when the envelope is not addressed to this recipient
// (or is corrupt at the carrier) — the normal "not mine" case during a poll —
// and a non-nil error only when an envelope that DID open for us fails
// signature verification (a forgery attempt).
func openEnvelope(recipient *crypto.Identity, raw []byte) (*opened, error) {
	if len(raw) < headerFixed {
		return nil, nil
	}
	if !bytes.Equal(raw[:4], magic[:]) || raw[4] != envVersion {
		return nil, nil
	}
	suiteID := raw[5]
	if suiteID != recipient.SuiteID {
		return nil, nil
	}
	s := crypto.Lookup(suiteID)
	if s == nil {
		return nil, nil
	}
	aad := raw[:headerFixed]
	r := &reader{b: raw, i: headerFixed}
	ephPub := r.lenU8()
	nonce := r.lenU8()
	ct := r.lenU32()
	if r.err != nil {
		return nil, nil
	}
	inner, err := crypto.OpenFrom(s, recipient.EncPriv, ephPub, nonce, ct, aad)
	if err != nil {
		return nil, nil // not addressed to us, or tampered
	}
	o, sig, err := decodeInner(inner)
	if err != nil {
		return nil, errFormat
	}
	ctx := sigContext(suiteID, recipient.EncPub, o.msgID, o.convID, o.seq, o.typ, o.payload)
	if !s.Verify(o.senderSigPub, ctx, sig) {
		return nil, errSig
	}
	return o, nil
}

// --- little-endian-free binary helpers ---

func writeU8(buf *bytes.Buffer, b []byte) error {
	if len(b) > 255 {
		return fmt.Errorf("drop: field exceeds 255 bytes")
	}
	buf.WriteByte(byte(len(b)))
	buf.Write(b)
	return nil
}

func writeU32(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

func writeU64(buf *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	buf.Write(x[:])
}

type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) u8() byte {
	if r.err != nil || r.i >= len(r.b) {
		r.err = errFormat
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *reader) u64() uint64 {
	if r.err != nil || r.i+8 > len(r.b) {
		r.err = errFormat
		return 0
	}
	v := binary.BigEndian.Uint64(r.b[r.i:])
	r.i += 8
	return v
}

func (r *reader) fixed(n int) []byte {
	if r.err != nil || r.i+n > len(r.b) {
		r.err = errFormat
		return nil
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out
}

func (r *reader) lenU8() []byte {
	if r.err != nil || r.i >= len(r.b) {
		r.err = errFormat
		return nil
	}
	n := int(r.b[r.i])
	r.i++
	return r.fixed(n)
}

func (r *reader) lenU32() []byte {
	if r.err != nil || r.i+4 > len(r.b) {
		r.err = errFormat
		return nil
	}
	n := int(binary.BigEndian.Uint32(r.b[r.i:]))
	r.i += 4
	return r.fixed(n)
}
