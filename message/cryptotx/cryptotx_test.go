package cryptotx

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	ddcrypto "deaddrop/crypto"
)

var (
	safeAddr  = common.HexToAddress("0x1111111111111111111111111111111111111111")
	tokenAddr = common.HexToAddress("0x2222222222222222222222222222222222222222")
	toAddr    = common.HexToAddress("0x3333333333333333333333333333333333333333")
)

func newTx() *SafeTx {
	return NewStablecoinTransfer(1, safeAddr, tokenAddr, toAddr, big.NewInt(1_000_000), 0)
}

func TestERC20TransferSelector(t *testing.T) {
	data := ERC20Transfer(toAddr, big.NewInt(5))
	if got := hex.EncodeToString(data[:4]); got != "a9059cbb" {
		t.Fatalf("transfer selector = %s; want a9059cbb", got)
	}
}

func TestSafeTxHashDeterministicAndSensitive(t *testing.T) {
	a := newTx()
	if a.Hash() != a.Hash() {
		t.Fatal("hash not deterministic")
	}
	b := newTx()
	b.Nonce = 1
	if a.Hash() == b.Hash() {
		t.Fatal("hash insensitive to nonce")
	}
	c := NewStablecoinTransfer(1, safeAddr, tokenAddr, toAddr, big.NewInt(2_000_000), 0)
	if a.Hash() == c.Hash() {
		t.Fatal("hash insensitive to amount")
	}
	d := NewStablecoinTransfer(137, safeAddr, tokenAddr, toAddr, big.NewInt(1_000_000), 0)
	if a.Hash() == d.Hash() {
		t.Fatal("hash insensitive to chainId")
	}
}

func TestSignRecoverVerify(t *testing.T) {
	tx := newTx()
	key, _ := ethcrypto.GenerateKey()
	addr, err := tx.SignWith(key)
	if err != nil {
		t.Fatal(err)
	}
	if addr != ethcrypto.PubkeyToAddress(key.PublicKey) {
		t.Fatal("signer address mismatch")
	}
	rec, err := tx.RecoverSigner(tx.Signatures[addr])
	if err != nil || rec != addr {
		t.Fatalf("recover = %s, %v; want %s", rec, err, addr)
	}
	if owners, err := tx.VerifyOwners(); err != nil || len(owners) != 1 {
		t.Fatalf("VerifyOwners = %v, %v", owners, err)
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	tx := newTx()
	// A signature filed under an address it does not recover to.
	bogus := make([]byte, 65)
	bogus[64] = 27
	tx.Signatures[toAddr] = bogus
	if _, err := tx.VerifyOwners(); err == nil {
		t.Fatal("forged signature accepted")
	}
}

func TestAggregateSortedAndThreshold(t *testing.T) {
	tx := newTx()
	k1, _ := ethcrypto.GenerateKey()
	k2, _ := ethcrypto.GenerateKey()
	a1, _ := tx.SignWith(k1)
	a2, _ := tx.SignWith(k2)

	if !tx.Reached(2) || tx.Reached(3) {
		t.Fatal("threshold logic wrong")
	}
	agg := tx.AggregatedSignatures()
	if len(agg) != 130 {
		t.Fatalf("aggregated len = %d; want 130", len(agg))
	}
	// Order must be ascending by signer address.
	lo, hi := a1, a2
	if bytes.Compare(a2.Bytes(), a1.Bytes()) < 0 {
		lo, hi = a2, a1
	}
	if !bytes.Equal(agg[:65], tx.Signatures[lo]) || !bytes.Equal(agg[65:], tx.Signatures[hi]) {
		t.Fatal("signatures not ordered by address")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tx := newTx()
	key, _ := ethcrypto.GenerateKey()
	tx.SignWith(key)

	raw, err := tx.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Handler{}.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := p.(*SafeTx)
	if got.Hash() != tx.Hash() {
		t.Fatal("hash changed across encode/decode")
	}
	if len(got.Signatures) != 1 {
		t.Fatalf("signatures lost: %d", len(got.Signatures))
	}
	if _, err := got.VerifyOwners(); err != nil {
		t.Fatalf("decoded signatures invalid: %v", err)
	}
}

func TestExecCalldata(t *testing.T) {
	tx := newTx()
	key, _ := ethcrypto.GenerateKey()
	tx.SignWith(key)
	call := BuildExecCall(tx)
	if call.To != safeAddr {
		t.Fatalf("exec call target = %s; want Safe", call.To)
	}
	if !bytes.Equal(call.Data[:4], execSelector) {
		t.Fatal("exec calldata selector mismatch")
	}
}

func TestHandlerRejectsForgedBeforeCallback(t *testing.T) {
	called := false
	h := Handler{OnSafeTx: func(_ ddcrypto.Contact, _ *SafeTx) { called = true }}

	tx := newTx()
	tx.Signatures[toAddr] = make([]byte, 65) // invalid
	raw, _ := tx.Encode()
	p, _ := h.Decode(raw)
	if err := h.Handle(ddcrypto.Contact{}, p); err == nil {
		t.Fatal("handler accepted forged signature")
	}
	if called {
		t.Fatal("callback invoked on forged tx")
	}
}
