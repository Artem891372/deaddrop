package message

import (
	"deaddrop/crypto"
	"deaddrop/drop"
)

// Service connects a mailbox (L1) to a handler registry (L3): it sends typed
// payloads and, on each poll, decrypts new messages and dispatches them to the
// registered handlers.
type Service struct {
	mb  *drop.Mailbox
	reg *Registry

	// AutoAck sends a delivery acknowledgement for each successfully handled
	// message, so the sender can garbage-collect its blob. Acking requires the
	// sender to be in the mailbox address book; failures are ignored.
	AutoAck bool
}

// NewService wires a mailbox and registry together with auto-ack enabled.
func NewService(mb *drop.Mailbox, reg *Registry) *Service {
	return &Service{mb: mb, reg: reg, AutoAck: true}
}

// Contact returns the underlying mailbox's own card.
func (s *Service) Contact() crypto.Contact { return s.mb.Contact() }

// AddContact registers a correspondent (its fingerprint verified out-of-band).
func (s *Service) AddContact(c crypto.Contact) { s.mb.AddContact(c) }

// Send seals and publishes a payload to a recipient, returning its message id.
func (s *Service) Send(to crypto.Contact, p Payload) ([16]byte, error) {
	data, err := p.Encode()
	if err != nil {
		return [16]byte{}, err
	}
	return s.mb.Send(to, p.Type(), data)
}

// Poll fetches new messages once and dispatches each to its handler. It returns
// the number of messages successfully handled. A message whose type is
// unregistered, or whose handler fails, is skipped (not acked). Carrier-level
// failures are returned as the error.
func (s *Service) Poll() (int, error) {
	ins, err := s.mb.Receive()
	if err != nil {
		return 0, err
	}
	handled := 0
	for _, in := range ins {
		if derr := s.reg.Dispatch(in.From, in.Type, in.Payload); derr != nil {
			continue
		}
		handled++
		if s.AutoAck {
			_ = s.mb.Ack(in)
		}
	}
	return handled, nil
}
