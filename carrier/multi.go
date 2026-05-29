package carrier

import "errors"

// Multi composes several carriers for continuity under blocking (T9, TR-F-5).
//
// Writes are mirrored to every backing carrier; a Put succeeds when at least
// `quorum` of them accept it, so blocking or failure of some carriers neither
// loses the message nor fails the publish. Reads merge the listings of all
// reachable carriers (an unreachable one is skipped); Get returns the first
// copy found. Because the upper layers use unique random blob names, the same
// blob carries the same name on every carrier, so listing-level deduplication
// is exact.
type Multi struct {
	carriers []Carrier
	quorum   int
}

// NewMulti composes carriers with the given write quorum (number of mirrors
// that must accept a Put for it to succeed). quorum is clamped to
// [1, len(carriers)]; a typical value is 2.
func NewMulti(quorum int, carriers ...Carrier) *Multi {
	if quorum < 1 {
		quorum = 1
	}
	if quorum > len(carriers) {
		quorum = len(carriers)
	}
	return &Multi{carriers: carriers, quorum: quorum}
}

func (m *Multi) Put(name string, data []byte) error {
	if !ValidName(name) {
		return ErrBadName
	}
	var ok int
	var errs []error
	for _, c := range m.carriers {
		if err := c.Put(name, data); err != nil {
			errs = append(errs, err)
			continue
		}
		ok++
	}
	if ok >= m.quorum {
		return nil
	}
	return errors.Join(errs...)
}

func (m *Multi) Get(name string) ([]byte, error) {
	var errs []error
	for _, c := range m.carriers {
		data, err := c.Get(name)
		if err == nil {
			return data, nil
		}
		if errors.Is(err, ErrNotExist) {
			continue
		}
		errs = append(errs, err)
	}
	// Reachable carriers that lacked the blob agreed it is absent; only report
	// ErrNotExist when none were merely unreachable, so a transient outage is
	// not mistaken for a definitive miss.
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, ErrNotExist
}

func (m *Multi) List() ([]string, error) {
	seen := make(map[string]struct{})
	var errs []error
	var anyOK bool
	for _, c := range m.carriers {
		names, err := c.List()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		anyOK = true
		for _, n := range names {
			seen[n] = struct{}{}
		}
	}
	if !anyOK && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out, nil
}

func (m *Multi) Delete(name string) error {
	var errs []error
	for _, c := range m.carriers {
		if err := c.Delete(name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
