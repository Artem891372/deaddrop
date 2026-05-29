// Package cryptotx is the cryptocurrency payload for DeadDrop's L3: cooperative
// signing of a Safe (EVM smart-contract multisig) transaction, the
// demonstration scenario for a business co-signing a stablecoin transfer
// asynchronously through an untrusted carrier.
//
// This is the only package that depends on go-ethereum (DR-7); the DeadDrop
// core (L0–L2) stays dependency-light. Two key systems meet here: the channel
// keys (Ed25519/X25519, package crypto) that protect transport, and the wallet
// keys (secp256k1) that sign the on-chain transaction.
package cryptotx

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Safe v1.3.0 EIP-712 type hashes.
var (
	domainTypeHash = ethcrypto.Keccak256([]byte(
		"EIP712Domain(uint256 chainId,address verifyingContract)"))
	safeTxTypeHash = ethcrypto.Keccak256([]byte(
		"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas," +
			"uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"))
	erc20TransferSelector = ethcrypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
)

// word left-pads b to a 32-byte ABI word.
func word(b []byte) []byte {
	w := make([]byte, 32)
	copy(w[32-len(b):], b)
	return w
}

func addrWord(a common.Address) []byte { return word(a.Bytes()) }

func uintWord(v *big.Int) []byte {
	if v == nil {
		return make([]byte, 32)
	}
	return word(v.Bytes())
}

func u64Word(v uint64) []byte { return uintWord(new(big.Int).SetUint64(v)) }

func domainSeparator(chainID uint64, safe common.Address) []byte {
	buf := append([]byte{}, domainTypeHash...)
	buf = append(buf, u64Word(chainID)...)
	buf = append(buf, addrWord(safe)...)
	return ethcrypto.Keccak256(buf)
}

// SafeTxHash computes the EIP-712 hash that each Safe owner signs.
func SafeTxHash(tx *SafeTx) common.Hash {
	dataHash := ethcrypto.Keccak256(tx.Data)
	var sb []byte
	sb = append(sb, safeTxTypeHash...)
	sb = append(sb, addrWord(tx.To)...)
	sb = append(sb, uintWord(tx.Value)...)
	sb = append(sb, word(dataHash)...)
	sb = append(sb, u64Word(uint64(tx.Operation))...)
	sb = append(sb, uintWord(tx.SafeTxGas)...)
	sb = append(sb, uintWord(tx.BaseGas)...)
	sb = append(sb, uintWord(tx.GasPrice)...)
	sb = append(sb, addrWord(tx.GasToken)...)
	sb = append(sb, addrWord(tx.RefundReceiver)...)
	sb = append(sb, u64Word(tx.Nonce)...)
	structHash := ethcrypto.Keccak256(sb)

	pre := []byte{0x19, 0x01}
	pre = append(pre, domainSeparator(tx.ChainID, tx.Safe)...)
	pre = append(pre, structHash...)
	return common.BytesToHash(ethcrypto.Keccak256(pre))
}

// ERC20Transfer builds the calldata for transfer(to, amount).
func ERC20Transfer(to common.Address, amount *big.Int) []byte {
	out := append([]byte{}, erc20TransferSelector...)
	out = append(out, addrWord(to)...)
	out = append(out, uintWord(amount)...)
	return out
}
