// Package message is layer L3 of DeadDrop: the pluggable payload types carried
// by the drop protocol, and a small service that ties a mailbox to a registry
// of handlers. The core (L0–L2) is independent of payload type; new types —
// chat text, cryptocurrency transactions — are added here without touching the
// lower layers.
package message

import (
	"errors"
	"sync"

	"deaddrop/crypto"
)

// ErrUnknownType is returned when no handler is registered for a payload type.
var ErrUnknownType = errors.New("message: unknown payload type")

// Payload is an application-level message body. Type is the tag carried in the
// envelope; Encode produces the bytes that are sealed.
type Payload interface {
	Type() string
	Encode() ([]byte, error)
}

// Handler decodes and acts on payloads of one type.
type Handler interface {
	Type() string
	Decode(data []byte) (Payload, error)
	Handle(from crypto.Contact, p Payload) error
}

// Registry resolves payload types to handlers. Safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{handlers: map[string]Handler{}}
}

// Register installs a handler for its type, replacing any previous one.
func (r *Registry) Register(h Handler) {
	r.mu.Lock()
	r.handlers[h.Type()] = h
	r.mu.Unlock()
}

func (r *Registry) handler(typ string) (Handler, bool) {
	r.mu.RLock()
	h, ok := r.handlers[typ]
	r.mu.RUnlock()
	return h, ok
}

// Decode turns raw payload bytes of the given type into a Payload.
func (r *Registry) Decode(typ string, data []byte) (Payload, error) {
	h, ok := r.handler(typ)
	if !ok {
		return nil, ErrUnknownType
	}
	return h.Decode(data)
}

// Dispatch decodes data and invokes the registered handler.
func (r *Registry) Dispatch(from crypto.Contact, typ string, data []byte) error {
	h, ok := r.handler(typ)
	if !ok {
		return ErrUnknownType
	}
	p, err := h.Decode(data)
	if err != nil {
		return err
	}
	return h.Handle(from, p)
}
