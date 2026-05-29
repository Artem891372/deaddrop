package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestSuiteLookup(t *testing.T) {
	if Lookup(SuiteModernID) == nil {
		t.Fatal("modern suite not registered")
	}
	if Lookup(0xFF) != nil {
		t.Fatal("unknown suite id resolved")
	}
}

func TestDHAgreement(t *testing.T) {
	s := Modern()
	aPriv, aPub, _ := s.GenerateKEMKey()
	bPriv, bPub, _ := s.GenerateKEMKey()
	ab, err := s.DH(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := s.DH(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("DH not symmetric")
	}
}

func TestSealRoundTrip(t *testing.T) {
	s := Modern()
	b, err := NewIdentity(s)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("transfer 100 USDT")
	aad := []byte("header")
	sealed, err := SealTo(s, b.EncPub, msg, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenFrom(s, b.EncPriv, sealed.EphPub, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip = %q; want %q", got, msg)
	}
}

func TestSealWrongRecipient(t *testing.T) {
	s := Modern()
	b, _ := NewIdentity(s)
	eve, _ := NewIdentity(s)
	sealed, _ := SealTo(s, b.EncPub, []byte("secret"), nil)
	if _, err := OpenFrom(s, eve.EncPriv, sealed.EphPub, sealed.Nonce, sealed.Ciphertext, nil); err == nil {
		t.Fatal("Open by wrong recipient succeeded")
	}
}

func TestSealTamper(t *testing.T) {
	s := Modern()
	b, _ := NewIdentity(s)
	aad := []byte("aad")
	sealed, _ := SealTo(s, b.EncPub, []byte("secret"), aad)

	// Tampered ciphertext.
	bad := append([]byte(nil), sealed.Ciphertext...)
	bad[0] ^= 0xFF
	if _, err := OpenFrom(s, b.EncPriv, sealed.EphPub, sealed.Nonce, bad, aad); err == nil {
		t.Fatal("Open of tampered ciphertext succeeded")
	}
	// Wrong AAD.
	if _, err := OpenFrom(s, b.EncPriv, sealed.EphPub, sealed.Nonce, sealed.Ciphertext, []byte("other")); err == nil {
		t.Fatal("Open with wrong AAD succeeded")
	}
}

func TestSignVerify(t *testing.T) {
	s := Modern()
	priv, pub, err := s.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("safeTxHash")
	sig := s.Sign(priv, msg)
	if !s.Verify(pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if s.Verify(pub, []byte("other"), sig) {
		t.Fatal("signature verified for wrong message")
	}
	_, otherPub, _ := s.GenerateSigningKey()
	if s.Verify(otherPub, msg, sig) {
		t.Fatal("signature verified under wrong key")
	}
}

func TestFingerprint(t *testing.T) {
	s := Modern()
	a, _ := NewIdentity(s)
	fp := a.Contact().Fingerprint()
	if fp != a.Contact().Fingerprint() {
		t.Fatal("fingerprint not stable")
	}
	if !strings.Contains(fp, "-") {
		t.Fatalf("fingerprint not grouped: %q", fp)
	}
	b, _ := NewIdentity(s)
	if a.Contact().Fingerprint() == b.Contact().Fingerprint() {
		t.Fatal("distinct identities share a fingerprint")
	}
}
