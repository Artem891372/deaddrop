package drop

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"deaddrop/carrier"
	"deaddrop/crypto"
)

// ackType is the payload type of a delivery acknowledgement; its payload is the
// 16-byte msg id being acknowledged. Acks are ordinary envelopes (sealed to the
// original sender), so the carrier cannot tell them apart from messages.
const ackType = "deaddrop/ack"

// Inbound is a received, decrypted and signature-verified message. From carries
// the full contact when the sender is in the address book, otherwise only the
// sender's signing key.
type Inbound struct {
	From      crypto.Contact
	ConvID    [16]byte
	Seq       uint64
	Type      string
	Payload   []byte
	MsgID     [16]byte
	Timestamp int64
	name      string // blob it arrived in (internal)
}

type convState struct {
	id   [16]byte
	next uint64
}

// Mailbox is a participant's view of one drop: it sends and receives envelopes
// over a Carrier under one Identity. Safe for concurrent use.
type Mailbox struct {
	car  carrier.Carrier
	id   *crypto.Identity
	rand io.Reader

	mu        sync.Mutex
	contacts  map[string]crypto.Contact // by sig pub (address book)
	seenNames map[string]struct{}       // carrier blobs already fetched
	seenMsg   map[[16]byte]struct{}     // accepted msg ids (replay guard)
	pending   map[[16]byte]string       // our sent msgID → blob name, awaiting ack
	convs     map[string]*convState     // per-recipient conversation (by sig pub)
}

// NewMailbox binds an identity to a carrier.
func NewMailbox(c carrier.Carrier, id *crypto.Identity) *Mailbox {
	return &Mailbox{
		car: c, id: id, rand: rand.Reader,
		contacts:  map[string]crypto.Contact{},
		seenNames: map[string]struct{}{},
		seenMsg:   map[[16]byte]struct{}{},
		pending:   map[[16]byte]string{},
		convs:     map[string]*convState{},
	}
}

// Contact returns this mailbox's own public card.
func (m *Mailbox) Contact() crypto.Contact { return m.id.Contact() }

// AddContact registers a correspondent so that acks and replies to them can be
// addressed. Callers verify the contact's fingerprint out-of-band first.
func (m *Mailbox) AddContact(c crypto.Contact) {
	m.mu.Lock()
	m.contacts[string(c.SigPub)] = c
	m.mu.Unlock()
}

func (m *Mailbox) random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(m.rand, b)
	return b, err
}

// convFor returns the conversation id and next sequence number for a recipient
// (caller holds m.mu).
func (m *Mailbox) convFor(to crypto.Contact) ([16]byte, uint64, error) {
	key := string(to.SigPub)
	cs := m.convs[key]
	if cs == nil {
		cs = &convState{}
		idb, err := m.random(16)
		if err != nil {
			return [16]byte{}, 0, err
		}
		copy(cs.id[:], idb)
		m.convs[key] = cs
	}
	seq := cs.next
	cs.next++
	return cs.id, seq, nil
}

// Send seals payload of the given type to `to` and publishes it, returning the
// message id. The blob is tracked until an ack arrives, at which point a later
// Receive garbage-collects it.
func (m *Mailbox) Send(to crypto.Contact, payloadType string, payload []byte) ([16]byte, error) {
	return m.send(to, payloadType, payload, true)
}

func (m *Mailbox) send(to crypto.Contact, payloadType string, payload []byte, track bool) ([16]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var msgID [16]byte
	convID, seq, err := m.convFor(to)
	if err != nil {
		return msgID, err
	}
	idb, err := m.random(16)
	if err != nil {
		return msgID, err
	}
	copy(msgID[:], idb)

	raw, err := sealEnvelope(m.id, to, msgID, convID, seq, time.Now().UnixMilli(), payloadType, payload)
	if err != nil {
		return msgID, err
	}
	nameb, err := m.random(16)
	if err != nil {
		return msgID, err
	}
	name := hex.EncodeToString(nameb)
	if err := m.car.Put(name, raw); err != nil {
		return msgID, err
	}
	if track {
		m.pending[msgID] = name
	}
	return msgID, nil
}

// Receive polls the drop once: it fetches new blobs, decrypts those addressed
// to us, discards replays, garbage-collects our sent blobs whose ack has
// arrived, and returns the new application messages. Acks are consumed
// internally and not surfaced.
func (m *Mailbox) Receive() ([]Inbound, error) {
	names, err := m.car.List()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var out []Inbound
	for _, name := range names {
		if _, ok := m.seenNames[name]; ok {
			continue
		}
		data, err := m.car.Get(name)
		if err != nil {
			continue // transient/vanished; retry on a later poll (not marked seen)
		}
		m.seenNames[name] = struct{}{}

		o, err := openEnvelope(m.id, data)
		if err != nil || o == nil {
			continue // not ours, corrupt, or forged
		}
		if _, dup := m.seenMsg[o.msgID]; dup {
			continue // replay
		}
		m.seenMsg[o.msgID] = struct{}{}

		if o.typ == ackType {
			m.handleAck(o.payload)
			_ = m.car.Delete(name) // ack consumed; remove it from the drop
			continue
		}

		from := crypto.Contact{SuiteID: m.id.SuiteID, SigPub: o.senderSigPub}
		if known, ok := m.contacts[string(o.senderSigPub)]; ok {
			from = known
		}
		out = append(out, Inbound{
			From: from, ConvID: o.convID, Seq: o.seq, Type: o.typ,
			Payload: o.payload, MsgID: o.msgID, Timestamp: o.timestamp, name: name,
		})
	}
	return out, nil
}

// handleAck garbage-collects the blob for an acknowledged message (caller holds
// m.mu).
func (m *Mailbox) handleAck(payload []byte) {
	if len(payload) != 16 {
		return
	}
	var id [16]byte
	copy(id[:], payload)
	if name, ok := m.pending[id]; ok {
		_ = m.car.Delete(name)
		delete(m.pending, id)
	}
}

// Ack acknowledges a received message to its sender, prompting the sender to
// garbage-collect the original blob. The sender must be in the address book
// (AddContact) so the ack can be sealed to them.
func (m *Mailbox) Ack(in Inbound) error {
	m.mu.Lock()
	to, ok := m.contacts[string(in.From.SigPub)]
	m.mu.Unlock()
	if !ok {
		return errUnknownContact
	}
	id := in.MsgID
	_, err := m.send(to, ackType, id[:], false)
	return err
}

// PendingCount reports how many sent messages are awaiting acknowledgement.
func (m *Mailbox) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}

var errUnknownContact = errString("drop: sender not in address book; AddContact first")

type errString string

func (e errString) Error() string { return string(e) }
