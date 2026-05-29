package cryptotx

import (
	"context"
	"crypto/ecdsa"
	"math/big"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var execSelector = ethcrypto.Keccak256([]byte(
	"execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"))[:4]

// ExecCall is a ready-to-broadcast call: invoke Data on To (the Safe contract).
type ExecCall struct {
	To   common.Address
	Data []byte
}

// BuildExecCall assembles the Safe.execTransaction call once enough signatures
// are collected. The result is sent by the operator's node — broadcasting is
// deliberately outside the secure channel (DR-8): the system transmits the
// artifact, it does not perform settlement.
func BuildExecCall(tx *SafeTx) ExecCall {
	return ExecCall{To: tx.Safe, Data: execCalldata(tx)}
}

// execCalldata ABI-encodes Safe.execTransaction(to,value,data,operation,
// safeTxGas,baseGas,gasPrice,gasToken,refundReceiver,signatures). `data` and
// `signatures` are dynamic (bytes); their offsets sit in the 10-word head and
// their contents in the tail.
func execCalldata(tx *SafeTx) []byte {
	sigs := tx.AggregatedSignatures()
	const headLen = 10 * 32

	dataTail := encodeBytesTail(tx.Data)
	sigTail := encodeBytesTail(sigs)

	head := make([][]byte, 10)
	head[0] = addrWord(tx.To)
	head[1] = uintWord(tx.Value)
	head[2] = u64Word(headLen) // offset of `data`
	head[3] = u64Word(uint64(tx.Operation))
	head[4] = uintWord(tx.SafeTxGas)
	head[5] = uintWord(tx.BaseGas)
	head[6] = uintWord(tx.GasPrice)
	head[7] = addrWord(tx.GasToken)
	head[8] = addrWord(tx.RefundReceiver)
	head[9] = u64Word(uint64(headLen + len(dataTail))) // offset of `signatures`

	out := append([]byte{}, execSelector...)
	for _, w := range head {
		out = append(out, w...)
	}
	out = append(out, dataTail...)
	out = append(out, sigTail...)
	return out
}

// encodeBytesTail ABI-encodes a dynamic bytes value: a length word followed by
// the content zero-padded to a 32-byte multiple.
func encodeBytesTail(b []byte) []byte {
	out := u64Word(uint64(len(b)))
	padded := (len(b) + 31) / 32 * 32
	buf := make([]byte, padded)
	copy(buf, b)
	return append(out, buf...)
}

// Submit broadcasts the collected SafeTx via execTransaction using a relayer
// key, returning the Ethereum transaction hash. It requires a live RPC node and
// a deployed Safe; broadcasting is the operator's responsibility, outside the
// secure channel.
func Submit(ctx context.Context, client *ethclient.Client, relayer *ecdsa.PrivateKey, tx *SafeTx) (common.Hash, error) {
	call := BuildExecCall(tx)
	from := ethcrypto.PubkeyToAddress(relayer.PublicKey)

	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return common.Hash{}, err
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	gas, err := client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &call.To, Data: call.Data})
	if err != nil {
		return common.Hash{}, err
	}
	ethTx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &call.To,
		Value:    big.NewInt(0),
		Gas:      gas,
		GasPrice: gasPrice,
		Data:     call.Data,
	})
	signed, err := types.SignTx(ethTx, types.LatestSignerForChainID(chainID), relayer)
	if err != nil {
		return common.Hash{}, err
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		return common.Hash{}, err
	}
	return signed.Hash(), nil
}
