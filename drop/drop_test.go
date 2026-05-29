package drop

import (
	"bytes"
	"errors"
	"testing"

	"deaddrop/carrier"
	"deaddrop/crypto"
)

func newID(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.NewIdentity(crypto.Modern())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEnvelopeRoundTrip(t *testing.T) {
	a, b := newID(t), newID(t)
	var msgID, convID [16]byte
	msgID[0], convID[0] = 1, 2
	payload := []byte("transfer 100 USDT")

	raw, err := sealEnvelope(a, b.Contact(), msgID, convID, 7, 12345, "text", payload)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openEnvelope(b, raw)
	if err != nil || o == nil {
		t.Fatalf("open: %v, %v", o, err)
	}
	if !bytes.Equal(o.payload, payload) || o.typ != "text" || o.seq != 7 {
		t.Fatalf("fields mismatch: %+v", o)
	}
	if !bytes.Equal(o.senderSigPub, a.SigPub) {
		t.Fatal("sender sig pub mismatch")
	}
	if o.msgID != msgID || o.convID != convID || o.timestamp != 12345 {
		t.Fatal("ids/timestamp mismatch")
	}
}

func TestEnvelopeNotForOthers(t *testing.T) {
	a, b, eve := newID(t), newID(t), newID(t)
	raw, _ := sealEnvelope(a, b.Contact(), [16]byte{}, [16]byte{}, 0, 0, "text", []byte("secret"))
	o, err := openEnvelope(eve, raw)
	if o != nil || err != nil {
		t.Fatalf("eve opened envelope: %v, %v", o, err)
	}
}

func TestEnvelopeTamperIsNotMine(t *testing.T) {
	a, b := newID(t), newID(t)
	raw, _ := sealEnvelope(a, b.Contact(), [16]byte{}, [16]byte{}, 0, 0, "text", []byte("secret"))
	raw[len(raw)-1] ^= 0xFF // corrupt last ciphertext byte
	o, err := openEnvelope(b, raw)
	if o != nil || err != nil {
		t.Fatalf("tampered envelope opened: %v, %v", o, err)
	}
}

// A forged envelope: the inner record claims sender A but is signed by Mallory.
// It decrypts for B (anyone can seal to B), so the signature is the only thing
// that exposes the forgery.
func TestEnvelopeForgedSignature(t *testing.T) {
	s := crypto.Modern()
	a, b, mallory := newID(t), newID(t), newID(t)
	var msgID, convID [16]byte
	payload := []byte("pay attacker")

	badSig := s.Sign(mallory.SigPriv, sigContext(s.ID(), b.EncPub, msgID, convID, 0, "text", payload))
	inner, err := encodeInner(a.SigPub, 0, msgID, convID, 0, "text", payload, badSig)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sealBytes(s, b.EncPub, inner)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openEnvelope(b, raw)
	if o != nil || !errors.Is(err, errSig) {
		t.Fatalf("forged signature accepted: %v, %v", o, err)
	}
}

func TestMailboxRoundTrip(t *testing.T) {
	car := carrier.NewMem()
	a, b := newID(t), newID(t)
	mbA := NewMailbox(car, a)
	mbB := NewMailbox(car, b)

	if _, err := mbA.Send(b.Contact(), "text", []byte("hello B")); err != nil {
		t.Fatal(err)
	}
	// Sender does not deliver to itself.
	if got, _ := mbA.Receive(); len(got) != 0 {
		t.Fatalf("sender received own message: %v", got)
	}
	got, err := mbB.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != "text" || string(got[0].Payload) != "hello B" {
		t.Fatalf("receive = %+v", got)
	}
	if !bytes.Equal(got[0].From.SigPub, a.SigPub) || got[0].Seq != 0 {
		t.Fatalf("sender/seq mismatch: %+v", got[0])
	}
	// Idempotent: a second poll yields nothing new.
	if again, _ := mbB.Receive(); len(again) != 0 {
		t.Fatalf("second receive returned %d", len(again))
	}
}

func TestMailboxReplayRejected(t *testing.T) {
	car := carrier.NewMem()
	a, b := newID(t), newID(t)
	mbA := NewMailbox(car, a)
	mbB := NewMailbox(car, b)

	mbA.Send(b.Contact(), "text", []byte("once"))
	names, _ := car.List()
	data, _ := car.Get(names[0])

	if got, _ := mbB.Receive(); len(got) != 1 {
		t.Fatalf("first receive = %d", len(got))
	}
	// Replay the same envelope under a fresh blob name.
	car.Put("replayed00000000000000000000dead", data)
	if got, _ := mbB.Receive(); len(got) != 0 {
		t.Fatalf("replay accepted: %d", len(got))
	}
}

func TestMailboxAckGarbageCollects(t *testing.T) {
	car := carrier.NewMem()
	a, b := newID(t), newID(t)
	mbA := NewMailbox(car, a)
	mbB := NewMailbox(car, b)
	mbB.AddContact(a.Contact())

	mbA.Send(b.Contact(), "text", []byte("deliver me"))
	if mbA.PendingCount() != 1 {
		t.Fatalf("pending = %d; want 1", mbA.PendingCount())
	}
	got, _ := mbB.Receive()
	if len(got) != 1 {
		t.Fatalf("receive = %d", len(got))
	}
	if err := mbB.Ack(got[0]); err != nil {
		t.Fatal(err)
	}
	// Sender consumes the ack and garbage-collects its blob (and the ack blob).
	if _, err := mbA.Receive(); err != nil {
		t.Fatal(err)
	}
	if mbA.PendingCount() != 0 {
		t.Fatalf("pending after ack = %d; want 0", mbA.PendingCount())
	}
	if names, _ := car.List(); len(names) != 0 {
		t.Fatalf("carrier not cleaned: %v", names)
	}
}

func TestMailboxSequence(t *testing.T) {
	car := carrier.NewMem()
	a, b := newID(t), newID(t)
	mbA := NewMailbox(car, a)
	mbB := NewMailbox(car, b)

	mbA.Send(b.Contact(), "text", []byte("m0"))
	mbA.Send(b.Contact(), "text", []byte("m1"))
	got, _ := mbB.Receive()
	if len(got) != 2 {
		t.Fatalf("receive = %d", len(got))
	}
	seqs := map[uint64]string{}
	conv := got[0].ConvID
	for _, in := range got {
		seqs[in.Seq] = string(in.Payload)
		if in.ConvID != conv {
			t.Fatal("conversation id not stable across messages")
		}
	}
	if seqs[0] != "m0" || seqs[1] != "m1" {
		t.Fatalf("sequence mismatch: %v", seqs)
	}
}
