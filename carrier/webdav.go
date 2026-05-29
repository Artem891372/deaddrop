package carrier

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebDAV is a Carrier backed by a WebDAV collection (e.g. Yandex.Disk). The
// drop is one collection on the server; blobs are files directly under it. A
// WebDAV PUT is atomic from a listing observer's perspective, so no temp+rename
// dance is needed. Auth is the full Authorization header value (e.g.
// "Basic <base64(user:app-password)>").
type WebDAV struct {
	endpoint string // trimmed origin, e.g. "https://webdav.yandex.ru"
	dropAbs  string // absolute collection path on the server, e.g. "/deaddrop"
	auth     string
	hc       *http.Client

	mu      sync.Mutex
	created bool // the drop collection has been ensured this process
}

const (
	davMaxRetries    = 6
	davRetryBackoff  = 500 * time.Millisecond
	davMaxBackoff    = 8 * time.Second
	davMaxRetryAfter = 30 * time.Second
	davReqTimeout    = 90 * time.Second
)

// NewWebDAV constructs a WebDAV carrier. endpoint is the server origin; drop is
// the collection path under which blobs live; auth is the full Authorization
// header value sent on every request.
func NewWebDAV(endpoint, auth, drop string) *WebDAV {
	return &WebDAV{
		endpoint: strings.TrimRight(endpoint, "/"),
		dropAbs:  "/" + strings.Trim(drop, "/"),
		auth:     auth,
		hc: &http.Client{
			Timeout: davReqTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
	}
}

func (c *WebDAV) url(absPath string) string {
	segs := strings.Split(strings.Trim(absPath, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return c.endpoint + "/" + strings.Join(segs, "/")
}

func (c *WebDAV) blobURL(name string) string { return c.url(c.dropAbs + "/" + name) }

// do issues one request with auth and retries transient failures (network
// errors, 429, 5xx). A 429/5xx Retry-After header is honoured in preference to
// the exponential backoff. The response body is owned by the caller.
func (c *WebDAV) do(method, rawURL string, body []byte, headers map[string]string) (*http.Response, error) {
	var lastErr error
	var wait time.Duration
	for attempt := 0; attempt <= davMaxRetries; attempt++ {
		if attempt > 0 {
			backoff := davRetryBackoff << (attempt - 1)
			if backoff > davMaxBackoff {
				backoff = davMaxBackoff
			}
			if wait > backoff {
				backoff = wait
			}
			time.Sleep(backoff)
			wait = 0
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, rawURL, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", c.auth)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if body != nil {
			req.ContentLength = int64(len(body))
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			wait = parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			lastErr = fmt.Errorf("webdav: %s: HTTP %d", method, resp.StatusCode)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}
	if d < 0 {
		return 0
	}
	if d > davMaxRetryAfter {
		return davMaxRetryAfter
	}
	return d
}

// ensure creates the drop collection (and its parents) once. MKCOL is not
// recursive; an existing collection is reported by Yandex as 405 or, when in
// use, 423 — both mean "already there".
func (c *WebDAV) ensure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.created {
		return nil
	}
	cur := ""
	for _, seg := range strings.Split(strings.Trim(c.dropAbs, "/"), "/") {
		if seg == "" {
			continue
		}
		cur += "/" + seg
		resp, err := c.do("MKCOL", c.url(cur), nil, nil)
		if err != nil {
			return err
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code/100 != 2 && code != http.StatusMethodNotAllowed && code != http.StatusLocked {
			return fmt.Errorf("webdav: MKCOL %s: HTTP %d", cur, code)
		}
	}
	c.created = true
	return nil
}

func (c *WebDAV) Put(name string, data []byte) error {
	if !ValidName(name) {
		return ErrBadName
	}
	if err := c.ensure(); err != nil {
		return err
	}
	resp, err := c.do(http.MethodPut, c.blobURL(name), data,
		map[string]string{"Content-Type": "application/octet-stream"})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webdav: PUT %s: HTTP %d", name, resp.StatusCode)
	}
	return nil
}

func (c *WebDAV) Get(name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrBadName
	}
	resp, err := c.do(http.MethodGet, c.blobURL(name), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webdav: GET %s: HTTP %d", name, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (c *WebDAV) Delete(name string) error {
	if !ValidName(name) {
		return ErrBadName
	}
	resp, err := c.do(http.MethodDelete, c.blobURL(name), nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode/100 == 2 {
		return nil
	}
	return fmt.Errorf("webdav: DELETE %s: HTTP %d", name, resp.StatusCode)
}

const davPropfindBody = `<?xml version="1.0" encoding="utf-8"?>` +
	`<propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>`

type davMultistatus struct {
	XMLName   xml.Name      `xml:"multistatus"`
	Responses []davResponse `xml:"response"`
}

type davResponse struct {
	Href     string `xml:"href"`
	Propstat []struct {
		Prop struct {
			ResourceType struct {
				Collection *struct{} `xml:"collection"`
			} `xml:"resourcetype"`
		} `xml:"prop"`
	} `xml:"propstat"`
}

func (r davResponse) isCollection() bool {
	for _, ps := range r.Propstat {
		if ps.Prop.ResourceType.Collection != nil {
			return true
		}
	}
	return false
}

// List returns the leaf blob names in the drop collection. A missing collection
// (404) lists as empty, per the Carrier contract. Sub-collections and the
// collection's own self-entry are skipped.
func (c *WebDAV) List() ([]string, error) {
	resp, err := c.do("PROPFIND", c.url(c.dropAbs), []byte(davPropfindBody),
		map[string]string{"Depth": "1", "Content-Type": `application/xml; charset="utf-8"`})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusMultiStatus {
		return nil, fmt.Errorf("webdav: PROPFIND %s: HTTP %d", c.dropAbs, resp.StatusCode)
	}
	var ms davMultistatus
	if err := xml.NewDecoder(resp.Body).Decode(&ms); err != nil {
		return nil, fmt.Errorf("webdav: PROPFIND parse: %w", err)
	}
	want := cleanPath(c.dropAbs)
	out := make([]string, 0, len(ms.Responses))
	for _, r := range ms.Responses {
		if cleanPath(r.Href) == want || r.isCollection() {
			continue
		}
		out = append(out, path.Base(cleanPath(r.Href)))
	}
	return out, nil
}

// cleanPath normalises a WebDAV href to an unescaped, slash-trimmed absolute
// path so the collection self-entry can be matched against the request.
func cleanPath(href string) string {
	hp := href
	if u, err := url.Parse(href); err == nil && u.Path != "" {
		hp = u.Path
	}
	if un, err := url.PathUnescape(hp); err == nil {
		hp = un
	}
	return "/" + strings.Trim(hp, "/")
}
