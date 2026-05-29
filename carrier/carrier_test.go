package carrier

import (
	"errors"
	"io"
	"sort"
	"testing"
)

// testContract exercises the Carrier contract against any implementation.
func testContract(t *testing.T, newC func() Carrier) {
	t.Helper()
	c := newC()

	// Empty drop lists as empty without error.
	if names, err := c.List(); err != nil || len(names) != 0 {
		t.Fatalf("empty List = %v, %v; want [], nil", names, err)
	}

	// Get of an absent blob is ErrNotExist.
	if _, err := c.Get("deadbeef"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Get missing = %v; want ErrNotExist", err)
	}

	// Put then Get round-trips.
	if err := c.Put("aa", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if data, err := c.Get("aa"); err != nil || string(data) != "hello" {
		t.Fatalf("Get aa = %q, %v; want hello", data, err)
	}

	// List reflects the blob.
	if names, _ := c.List(); !equalSet(names, []string{"aa"}) {
		t.Fatalf("List = %v; want [aa]", names)
	}

	// Put overwrites.
	if err := c.Put("aa", []byte("world")); err != nil {
		t.Fatalf("Put overwrite: %v", err)
	}
	if data, _ := c.Get("aa"); string(data) != "world" {
		t.Fatalf("Get after overwrite = %q; want world", data)
	}

	// Delete is idempotent and removes the blob.
	if err := c.Delete("aa"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := c.Delete("aa"); err != nil {
		t.Fatalf("Delete (idempotent): %v", err)
	}
	if _, err := c.Get("aa"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Get after Delete = %v; want ErrNotExist", err)
	}

	// Invalid names are rejected at the boundary.
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b", "x\x00y"} {
		if err := c.Put(bad, []byte("x")); !errors.Is(err, ErrBadName) {
			t.Fatalf("Put(%q) = %v; want ErrBadName", bad, err)
		}
	}
}

func TestMemContract(t *testing.T) { testContract(t, func() Carrier { return NewMem() }) }

func TestFSContract(t *testing.T) {
	testContract(t, func() Carrier { return NewFS(t.TempDir()) })
}

func TestMultiContract(t *testing.T) {
	testContract(t, func() Carrier { return NewMulti(2, NewMem(), NewMem()) })
}

// Mem must not alias caller or stored buffers.
func TestMemCopySemantics(t *testing.T) {
	c := NewMem()
	in := []byte("abc")
	c.Put("k", in)
	in[0] = 'X' // mutate caller buffer after Put
	out, _ := c.Get("k")
	if string(out) != "abc" {
		t.Fatalf("stored blob aliased caller buffer: %q", out)
	}
	out[0] = 'Y' // mutate returned buffer
	again, _ := c.Get("k")
	if string(again) != "abc" {
		t.Fatalf("Get returned aliased buffer: %q", again)
	}
}

type errCarrier struct{ err error }

func (e errCarrier) Put(string, []byte) error   { return e.err }
func (e errCarrier) Get(string) ([]byte, error) { return nil, e.err }
func (e errCarrier) List() ([]string, error)    { return nil, e.err }
func (e errCarrier) Delete(string) error        { return e.err }

func TestMultiMirrorsWrites(t *testing.T) {
	a, b := NewMem(), NewMem()
	m := NewMulti(2, a, b)
	if err := m.Put("x", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for i, c := range []*Mem{a, b} {
		if data, err := c.Get("x"); err != nil || string(data) != "v" {
			t.Fatalf("carrier %d missing mirror: %q, %v", i, data, err)
		}
	}
}

func TestMultiQuorum(t *testing.T) {
	// quorum 2 but only one healthy carrier → Put fails.
	m := NewMulti(2, NewMem(), errCarrier{io.ErrClosedPipe})
	if err := m.Put("x", []byte("v")); err == nil {
		t.Fatal("Put: want error when quorum unmet")
	}
	// quorum 1 with one healthy carrier → Put succeeds.
	m2 := NewMulti(1, NewMem(), errCarrier{io.ErrClosedPipe})
	if err := m2.Put("x", []byte("v")); err != nil {
		t.Fatalf("Put quorum 1: %v", err)
	}
}

func TestMultiReadFailover(t *testing.T) {
	a, b := NewMem(), NewMem()
	b.Put("only-on-b", []byte("v"))
	m := NewMulti(1, a, b)
	if data, err := m.Get("only-on-b"); err != nil || string(data) != "v" {
		t.Fatalf("failover Get = %q, %v; want v", data, err)
	}
}

func TestMultiListMergeAndDedup(t *testing.T) {
	a, b := NewMem(), NewMem()
	a.Put("x", []byte("1"))
	b.Put("y", []byte("2"))
	b.Put("x", []byte("1")) // duplicate name across carriers
	m := NewMulti(1, a, b)
	names, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !equalSet(names, []string{"x", "y"}) {
		t.Fatalf("List = %v; want {x,y} deduped", names)
	}
}

func TestMultiGetMissVsUnreachable(t *testing.T) {
	// All reachable, blob absent → ErrNotExist.
	m := NewMulti(1, NewMem(), NewMem())
	if _, err := m.Get("nope"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Get reachable miss = %v; want ErrNotExist", err)
	}
	// Unreachable carrier, blob not found → transient error, not ErrNotExist.
	m2 := NewMulti(1, errCarrier{io.ErrClosedPipe})
	if _, err := m2.Get("nope"); err == nil || errors.Is(err, ErrNotExist) {
		t.Fatalf("Get unreachable = %v; want transient error", err)
	}
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]string(nil), a...)
	cb := append([]string(nil), b...)
	sort.Strings(ca)
	sort.Strings(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}
