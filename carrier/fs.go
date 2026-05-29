package carrier

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// tmpPrefix marks in-progress writes. Real blob names never start with a dot
// (the upper layers use hex), so List skips dot-prefixed entries and never
// exposes a half-written file.
const tmpPrefix = ".ddtmp-"

// FS is a Carrier backed by a local directory (the "drop"). The directory may
// itself be a mounted cloud. Publish is atomic via write-to-temp + rename
// within the same directory.
type FS struct {
	root string
}

// NewFS returns a filesystem carrier rooted at dir. The directory is created
// lazily on first Put.
func NewFS(dir string) *FS {
	return &FS{root: dir}
}

func (c *FS) Put(name string, data []byte) error {
	if !ValidName(name) {
		return ErrBadName
	}
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.root, tmpPrefix+"*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail out before the rename succeeds.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(c.root, name))
}

func (c *FS) Get(name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrBadName
	}
	data, err := os.ReadFile(filepath.Join(c.root, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotExist
	}
	return data, err
}

func (c *FS) List() ([]string, error) {
	ents, err := os.ReadDir(c.root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // missing drop lists as empty, per contract
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue // temp/hidden files are not blobs
		}
		out = append(out, e.Name())
	}
	return out, nil
}

func (c *FS) Delete(name string) error {
	if !ValidName(name) {
		return ErrBadName
	}
	err := os.Remove(filepath.Join(c.root, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil // idempotent
	}
	return err
}
