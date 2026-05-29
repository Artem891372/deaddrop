// Package carrier is layer L0 of DeadDrop: the untrusted-carrier abstraction.
//
// A Carrier is a flat namespace of named blobs ("a drop") with four operations
// — Put, Get, List, Delete. It is the lowest common denominator across the
// media DeadDrop can ride on: a local folder, a mounted cloud, WebDAV, or
// several of those composed for resilience. The carrier is assumed UNTRUSTED:
// it may read, alter, delete, reorder, replay or block blobs. All security
// (confidentiality, integrity, authenticity, anonymity) is provided by the
// upper layers (drop, crypto), never by the carrier; this layer only stores and
// retrieves bytes and provides continuity under blocking via composition.
package carrier

import (
	"errors"
	"strings"
)

// ErrNotExist is returned by Get when a blob is absent. Delete treats a missing
// blob as success (idempotent), and List of a missing drop yields an empty
// slice without error — callers cannot distinguish "empty" from "unreadable"
// through List alone, by design.
var ErrNotExist = errors.New("carrier: blob does not exist")

// Carrier is a flat namespace of named blobs with atomic publish.
//
// Contract:
//   - Put publishes data under name atomically from a List observer's point of
//     view (the blob appears whole or not at all); an existing blob is
//     overwritten.
//   - Get returns the blob, or ErrNotExist if absent.
//   - List returns the blob names currently in the drop; a missing/empty drop
//     yields an empty slice and a nil error.
//   - Delete removes a blob and is idempotent (absent blob is success).
//
// Names are opaque leaf identifiers (see ValidName); the upper layers use
// random names so that the carrier learns nothing from them.
type Carrier interface {
	Put(name string, data []byte) error
	Get(name string) ([]byte, error)
	List() ([]string, error)
	Delete(name string) error
}

// ErrBadName is returned for a name that is unsafe as a storage leaf.
var ErrBadName = errors.New("carrier: invalid blob name")

// ValidName reports whether name is a safe leaf identifier: non-empty, not "."
// or "..", and free of path separators and NUL. This is a security boundary —
// it prevents a crafted name from escaping the drop directory in filesystem-
// backed carriers (path traversal).
func ValidName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if len(name) > 255 {
		return false
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	return true
}
