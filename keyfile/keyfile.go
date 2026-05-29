// Package keyfile persists DeadDrop identities and contacts as hex-encoded JSON
// files, shared by the abox CLI and the aboxtui front-end.
package keyfile

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"deaddrop/crypto"
)

type fileIdentity struct {
	Suite   byte   `json:"suite"`
	EncPriv string `json:"encPriv"`
	EncPub  string `json:"encPub"`
	SigPriv string `json:"sigPriv"`
	SigPub  string `json:"sigPub"`
}

type fileContact struct {
	Suite  byte   `json:"suite"`
	EncPub string `json:"encPub"`
	SigPub string `json:"sigPub"`
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

// SaveIdentity writes id to path with 0600 permissions (it holds secrets).
func SaveIdentity(path string, id *crypto.Identity) error {
	f := fileIdentity{
		Suite:   id.SuiteID,
		EncPriv: hex.EncodeToString(id.EncPriv), EncPub: hex.EncodeToString(id.EncPub),
		SigPriv: hex.EncodeToString(id.SigPriv), SigPub: hex.EncodeToString(id.SigPub),
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// LoadIdentity reads an identity file.
func LoadIdentity(path string) (*crypto.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f fileIdentity
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &crypto.Identity{
		SuiteID: f.Suite,
		EncPriv: mustHex(f.EncPriv), EncPub: mustHex(f.EncPub),
		SigPriv: mustHex(f.SigPriv), SigPub: mustHex(f.SigPub),
	}, nil
}

// LoadContact reads a contact file.
func LoadContact(path string) (crypto.Contact, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return crypto.Contact{}, err
	}
	var f fileContact
	if err := json.Unmarshal(b, &f); err != nil {
		return crypto.Contact{}, err
	}
	return crypto.Contact{SuiteID: f.Suite, EncPub: mustHex(f.EncPub), SigPub: mustHex(f.SigPub)}, nil
}

// ContactJSON renders a contact as indented hex JSON (suitable for a .contact
// file).
func ContactJSON(c crypto.Contact) string {
	b, _ := json.MarshalIndent(fileContact{
		Suite: c.SuiteID, EncPub: hex.EncodeToString(c.EncPub), SigPub: hex.EncodeToString(c.SigPub),
	}, "", "  ")
	return string(b)
}
