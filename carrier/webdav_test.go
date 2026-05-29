package carrier

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// memDAV is a tiny in-memory WebDAV server for tests — just enough of
// PROPFIND/GET/PUT/DELETE/MKCOL to exercise the WebDAV carrier without a real
// backend. Adapted from rctun's memdav.
type memDAV struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
}

func newMemDAV() *memDAV {
	return &memDAV{
		files: map[string][]byte{},
		dirs:  map[string]bool{"/": true},
	}
}

func davNorm(p string) string { return "/" + strings.Trim(p, "/") }

func (s *memDAV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := davNorm(r.URL.Path)
	s.mu.Lock()
	defer s.mu.Unlock()

	switch r.Method {
	case http.MethodGet:
		if b, ok := s.files[p]; ok {
			_, _ = w.Write(b)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		s.files[p] = b
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if _, ok := s.files[p]; ok {
			delete(s.files, p)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if s.dirs[p] {
			delete(s.dirs, p)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	case "MKCOL":
		if _, isFile := s.files[p]; isFile || s.dirs[p] {
			http.Error(w, "exists", http.StatusMethodNotAllowed)
			return
		}
		s.dirs[p] = true
		w.WriteHeader(http.StatusCreated)
	case "PROPFIND":
		s.propfind(w, r, p)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *memDAV) propfind(w http.ResponseWriter, r *http.Request, p string) {
	_, isFile := s.files[p]
	isDir := s.dirs[p]
	if !isFile && !isDir {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	entries := []string{p}
	if isDir && r.Header.Get("Depth") != "0" {
		for fp := range s.files {
			if path.Dir(fp) == p {
				entries = append(entries, fp)
			}
		}
		for dp := range s.dirs {
			if dp != p && path.Dir(dp) == p {
				entries = append(entries, dp)
			}
		}
	}
	sort.Strings(entries)

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<d:multistatus xmlns:d="DAV:">`)
	for _, e := range entries {
		b.WriteString(`<d:response><d:href>`)
		b.WriteString(e)
		b.WriteString(`</d:href><d:propstat><d:prop><d:resourcetype>`)
		if s.dirs[e] {
			b.WriteString(`<d:collection/>`)
		}
		b.WriteString(`</d:resourcetype>`)
		if data, ok := s.files[e]; ok {
			fmt.Fprintf(&b, `<d:getcontentlength>%d</d:getcontentlength>`, len(data))
		}
		fmt.Fprintf(&b, `<d:getlastmodified>%s</d:getlastmodified>`,
			time.Unix(0, 0).UTC().Format(http.TimeFormat))
		b.WriteString(`</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`)
	}
	b.WriteString(`</d:multistatus>`)

	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = io.WriteString(w, b.String())
}

func TestWebDAVContract(t *testing.T) {
	testContract(t, func() Carrier {
		srv := httptest.NewServer(newMemDAV())
		t.Cleanup(srv.Close)
		return NewWebDAV(srv.URL, "Basic test", "/deaddrop")
	})
}

func TestWebDAVMultiContract(t *testing.T) {
	testContract(t, func() Carrier {
		a := httptest.NewServer(newMemDAV())
		b := httptest.NewServer(newMemDAV())
		t.Cleanup(a.Close)
		t.Cleanup(b.Close)
		return NewMulti(2,
			NewWebDAV(a.URL, "Basic test", "/deaddrop"),
			NewWebDAV(b.URL, "Basic test", "/deaddrop"),
		)
	})
}
