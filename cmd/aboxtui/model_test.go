package main

import (
	"math/big"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"deaddrop/carrier"
	"deaddrop/crypto"
	"deaddrop/drop"
	"deaddrop/message"
	"deaddrop/message/cryptotx"
)

// drives the model without a terminal: feed a poll result and inspect the log.
func newTestModel(t *testing.T) (model, crypto.Contact) {
	t.Helper()
	me, err := crypto.NewIdentity(crypto.Modern())
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := crypto.NewIdentity(crypto.Modern())
	if err != nil {
		t.Fatal(err)
	}
	mb := drop.NewMailbox(carrier.NewMem(), me)
	mb.AddContact(peerID.Contact())
	m := newModel(mb, me, peerID.Contact(), nil, 2, time.Second)
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	return nm.(model), peerID.Contact()
}

func TestModelReceivesText(t *testing.T) {
	m, peer := newTestModel(t)
	in := drop.Inbound{From: peer, Type: message.TextType, Payload: []byte("hi there")}
	nm, _ := m.Update(polledMsg{ins: []drop.Inbound{in}})
	m = nm.(model)
	if !logContains(m, "hi there") {
		t.Fatalf("text not in log: %v", m.log)
	}
}

func TestModelReceivesAndStoresSafeTx(t *testing.T) {
	m, peer := newTestModel(t)
	tx := cryptotx.NewStablecoinTransfer(1,
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
		common.HexToAddress("0x3333333333333333333333333333333333333333"),
		big.NewInt(1000), 0)
	key, _ := ethcrypto.GenerateKey()
	if _, err := tx.SignWith(key); err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.Encode()
	in := drop.Inbound{From: peer, Type: cryptotx.SafeTxType, Payload: raw}
	nm, _ := m.Update(polledMsg{ins: []drop.Inbound{in}})
	m = nm.(model)
	if m.pending == nil {
		t.Fatal("safe-tx not stored as pending")
	}
	if !logContains(m, "safe-tx") {
		t.Fatalf("safe-tx not announced in log: %v", m.log)
	}
}

func TestModelRejectsForgedSafeTx(t *testing.T) {
	m, peer := newTestModel(t)
	tx := cryptotx.NewStablecoinTransfer(1, common.Address{}, common.Address{}, common.Address{}, big.NewInt(1), 0)
	tx.Signatures[common.HexToAddress("0x4444444444444444444444444444444444444444")] = make([]byte, 65) // invalid
	raw, _ := tx.Encode()
	in := drop.Inbound{From: peer, Type: cryptotx.SafeTxType, Payload: raw}
	nm, _ := m.Update(polledMsg{ins: []drop.Inbound{in}})
	m = nm.(model)
	if m.pending != nil {
		t.Fatal("forged safe-tx stored as pending")
	}
	if !logContains(m, "REJECTED") {
		t.Fatalf("forged tx not flagged: %v", m.log)
	}
}

func logContains(m model, sub string) bool {
	for _, l := range m.log {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
