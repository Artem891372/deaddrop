package message

import (
	"testing"

	"deaddrop/carrier"
	"deaddrop/crypto"
	"deaddrop/drop"
)

func newID(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.NewIdentity(crypto.Modern())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRegistryUnknownType(t *testing.T) {
	reg := NewRegistry()
	if _, err := reg.Decode("nope", nil); err != ErrUnknownType {
		t.Fatalf("Decode unknown = %v; want ErrUnknownType", err)
	}
	if err := reg.Dispatch(crypto.Contact{}, "nope", nil); err != ErrUnknownType {
		t.Fatalf("Dispatch unknown = %v; want ErrUnknownType", err)
	}
}

func TestTextRoundTripThroughService(t *testing.T) {
	car := carrier.NewMem()
	a, b := newID(t), newID(t)

	svcA := NewService(drop.NewMailbox(car, a), NewRegistry())

	var got []Text
	var gotFrom []crypto.Contact
	regB := NewRegistry()
	regB.Register(TextHandler{OnText: func(from crypto.Contact, tx Text) {
		got = append(got, tx)
		gotFrom = append(gotFrom, from)
	}})
	mbB := drop.NewMailbox(car, b)
	mbB.AddContact(a.Contact()) // so auto-ack can address the sender
	svcB := NewService(mbB, regB)

	if _, err := svcA.Send(b.Contact(), Text{Body: "hello via L3"}); err != nil {
		t.Fatal(err)
	}
	n, err := svcB.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(got) != 1 || got[0].Body != "hello via L3" {
		t.Fatalf("poll handled=%d got=%v", n, got)
	}
	if len(gotFrom) != 1 || string(gotFrom[0].SigPub) != string(a.SigPub) {
		t.Fatal("sender contact mismatch")
	}

	// Auto-ack lets the sender GC its blob on its next poll.
	svcA.Poll()
	if names, _ := car.List(); len(names) != 0 {
		t.Fatalf("carrier not cleaned after ack: %v", names)
	}
}

func TestUnknownTypeNotHandledNotAcked(t *testing.T) {
	car := carrier.NewMem()
	a, b := newID(t), newID(t)
	// A sends a type B has no handler for.
	mbA := drop.NewMailbox(car, a)
	mbA.Send(b.Contact(), "exotic", []byte("x"))

	svcB := NewService(drop.NewMailbox(car, b), NewRegistry())
	n, err := svcB.Poll()
	if err != nil || n != 0 {
		t.Fatalf("poll = %d, %v; want 0, nil", n, err)
	}
}
