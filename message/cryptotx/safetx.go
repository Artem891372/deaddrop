package cryptotx

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	ddcrypto "deaddrop/crypto"
	"deaddrop/message"
)

// SafeTxType is the DeadDrop payload tag for a Safe co-signing message.
const SafeTxType = "deaddrop/safe-tx"

var errSigLen = errors.New("cryptotx: signature must be 65 bytes")

// SafeTx is a Safe transaction plus the owner signatures collected so far. It
// travels as a DeadDrop payload between co-signers; each independently
// recomputes its hash and verifies the existing signatures before adding its
// own (TR-S-11, defends T13).
type SafeTx struct {
	ChainID        uint64                    `json:"chainId"`
	Safe           common.Address            `json:"safe"`
	To             common.Address            `json:"to"`
	Value          *big.Int                  `json:"value"`
	Data           []byte                    `json:"data"`
	Operation      uint8                     `json:"operation"`
	SafeTxGas      *big.Int                  `json:"safeTxGas"`
	BaseGas        *big.Int                  `json:"baseGas"`
	GasPrice       *big.Int                  `json:"gasPrice"`
	GasToken       common.Address            `json:"gasToken"`
	RefundReceiver common.Address            `json:"refundReceiver"`
	Nonce          uint64                    `json:"nonce"`
	Signatures     map[common.Address][]byte `json:"signatures"`
}

// NewStablecoinTransfer builds an unsigned SafeTx that moves `amount` of an
// ERC-20 stablecoin (`token`) from the Safe to `to`.
func NewStablecoinTransfer(chainID uint64, safe, token, to common.Address, amount *big.Int, nonce uint64) *SafeTx {
	return &SafeTx{
		ChainID:    chainID,
		Safe:       safe,
		To:         token,
		Value:      big.NewInt(0),
		Data:       ERC20Transfer(to, amount),
		Operation:  0, // CALL
		SafeTxGas:  big.NewInt(0),
		BaseGas:    big.NewInt(0),
		GasPrice:   big.NewInt(0),
		Nonce:      nonce,
		Signatures: map[common.Address][]byte{},
	}
}

// Hash is the EIP-712 safeTxHash owners sign.
func (tx *SafeTx) Hash() common.Hash { return SafeTxHash(tx) }

// --- message.Payload ---

func (*SafeTx) Type() string { return SafeTxType }

func (tx *SafeTx) Encode() ([]byte, error) { return json.Marshal(tx) }

// --- owner signing (secp256k1 wallet keys) ---

// SignWith signs the safeTxHash with an owner's wallet key and stores the
// signature (65 bytes, v in {27,28} as the Safe contract expects for an
// EIP-712 ECDSA signature). It returns the owner address.
func (tx *SafeTx) SignWith(key *ecdsa.PrivateKey) (common.Address, error) {
	sig, err := ethcrypto.Sign(tx.Hash().Bytes(), key) // 65 bytes, v in {0,1}
	if err != nil {
		return common.Address{}, err
	}
	sig[64] += 27
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	if tx.Signatures == nil {
		tx.Signatures = map[common.Address][]byte{}
	}
	tx.Signatures[addr] = sig
	return addr, nil
}

// RecoverSigner returns the address that produced sig over this tx's hash.
func (tx *SafeTx) RecoverSigner(sig []byte) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, errSigLen
	}
	s := append([]byte(nil), sig...)
	if s[64] >= 27 {
		s[64] -= 27
	}
	pub, err := ethcrypto.SigToPub(tx.Hash().Bytes(), s)
	if err != nil {
		return common.Address{}, err
	}
	return ethcrypto.PubkeyToAddress(*pub), nil
}

// VerifyOwners checks that every stored signature recovers to the owner address
// it is filed under, returning the verified owner addresses. A mismatch (a
// forged or tampered signature) is an error.
func (tx *SafeTx) VerifyOwners() ([]common.Address, error) {
	owners := make([]common.Address, 0, len(tx.Signatures))
	for addr, sig := range tx.Signatures {
		rec, err := tx.RecoverSigner(sig)
		if err != nil {
			return nil, err
		}
		if rec != addr {
			return nil, fmt.Errorf("cryptotx: signature filed under %s recovers to %s", addr, rec)
		}
		owners = append(owners, addr)
	}
	return owners, nil
}

// Reached reports whether at least `threshold` distinct owner signatures are
// present.
func (tx *SafeTx) Reached(threshold int) bool { return len(tx.Signatures) >= threshold }

// AggregatedSignatures concatenates the signatures ordered by signer address
// ascending — the format Safe.execTransaction requires.
func (tx *SafeTx) AggregatedSignatures() []byte {
	addrs := make([]common.Address, 0, len(tx.Signatures))
	for a := range tx.Signatures {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return bytes.Compare(addrs[i].Bytes(), addrs[j].Bytes()) < 0
	})
	var out []byte
	for _, a := range addrs {
		out = append(out, tx.Signatures[a]...)
	}
	return out
}

// --- message.Handler ---

// Handler decodes safe-tx payloads and forwards them to OnSafeTx, which is the
// co-signer's hook: re-verify and either add a signature and re-send, or, once
// the threshold is met, submit on-chain.
type Handler struct {
	OnSafeTx func(from ddcrypto.Contact, tx *SafeTx)
}

func (Handler) Type() string { return SafeTxType }

func (Handler) Decode(data []byte) (message.Payload, error) {
	var tx SafeTx
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

func (h Handler) Handle(from ddcrypto.Contact, p message.Payload) error {
	tx, ok := p.(*SafeTx)
	if !ok {
		return fmt.Errorf("cryptotx: unexpected payload %T", p)
	}
	if _, err := tx.VerifyOwners(); err != nil {
		return err // reject forged/tampered co-signer signatures
	}
	if h.OnSafeTx != nil {
		h.OnSafeTx(from, tx)
	}
	return nil
}
