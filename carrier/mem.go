package carrier

import "sync"

// Mem is an in-memory Carrier. It is safe for concurrent use and is primarily
// for tests and as the reference implementation of the contract.
type Mem struct {
	mu    sync.RWMutex
	blobs map[string][]byte
}

// NewMem returns an empty in-memory carrier.
func NewMem() *Mem {
	return &Mem{blobs: make(map[string][]byte)}
}

func (m *Mem) Put(name string, data []byte) error {
	if !ValidName(name) {
		return ErrBadName
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.mu.Lock()
	m.blobs[name] = cp
	m.mu.Unlock()
	return nil
}

func (m *Mem) Get(name string) ([]byte, error) {
	m.mu.RLock()
	data, ok := m.blobs[name]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotExist
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (m *Mem) List() ([]string, error) {
	m.mu.RLock()
	out := make([]string, 0, len(m.blobs))
	for name := range m.blobs {
		out = append(out, name)
	}
	m.mu.RUnlock()
	return out, nil
}

func (m *Mem) Delete(name string) error {
	m.mu.Lock()
	delete(m.blobs, name)
	m.mu.Unlock()
	return nil
}
