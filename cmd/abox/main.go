// Command abox is a demonstration CLI for DeadDrop: it generates identities,
// exchanges text messages, and runs a Safe (EVM) multisig co-signing flow over
// a carrier-backed drop. The drop here is a filesystem directory; in real use
// it would be a shared cloud folder (an untrusted carrier).
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"deaddrop/carrier"
	"deaddrop/crypto"
	"deaddrop/drop"
	"deaddrop/message"
	"deaddrop/message/cryptotx"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(args)
	case "contact":
		cmdContact(args)
	case "send":
		cmdSend(args)
	case "recv":
		cmdRecv(args)
	case "safe-propose":
		cmdSafePropose(args)
	case "safe-cosign":
		cmdSafeCosign(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `abox <command> [flags]

  keygen       -out FILE                         generate an identity
  contact      -id FILE                          print public contact + fingerprint
  send         -id -drop -to -text               send a text message
  recv         -id -drop [-interval]             receive text messages
  safe-propose -id -drop -to -wallet -chain -safe -token -dest -amount -nonce
               build, sign and send a Safe stablecoin transfer to a co-signer
  safe-cosign  -id -drop -wallet -threshold [-rpc -relayer]
               receive a Safe tx, co-sign, and on threshold print/submit execTransaction`)
	os.Exit(2)
}

// --- identity / contact persistence (hex JSON) ---

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

func saveIdentity(path string, id *crypto.Identity) error {
	f := fileIdentity{
		Suite:   id.SuiteID,
		EncPriv: hex.EncodeToString(id.EncPriv), EncPub: hex.EncodeToString(id.EncPub),
		SigPriv: hex.EncodeToString(id.SigPriv), SigPub: hex.EncodeToString(id.SigPub),
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

func loadIdentity(path string) (*crypto.Identity, error) {
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

func loadContact(path string) (crypto.Contact, error) {
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

func contactJSON(c crypto.Contact) string {
	b, _ := json.MarshalIndent(fileContact{
		Suite: c.SuiteID, EncPub: hex.EncodeToString(c.EncPub), SigPub: hex.EncodeToString(c.SigPub),
	}, "", "  ")
	return string(b)
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

// --- commands ---

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "identity.json", "identity output file")
	fs.Parse(args)

	id, err := crypto.NewIdentity(crypto.Modern())
	check(err)
	check(saveIdentity(*out, id))
	fmt.Printf("identity written to %s\nfingerprint: %s\n\ncontact:\n%s\n",
		*out, id.Contact().Fingerprint(), contactJSON(id.Contact()))
}

func cmdContact(args []string) {
	fs := flag.NewFlagSet("contact", flag.ExitOnError)
	idFile := fs.String("id", "identity.json", "identity file")
	fs.Parse(args)
	id, err := loadIdentity(*idFile)
	check(err)
	fmt.Fprintf(os.Stderr, "fingerprint: %s\n", id.Contact().Fingerprint())
	fmt.Println(contactJSON(id.Contact())) // stdout only → redirectable to a contact file
}

func openService(idFile, dropDir string) (*message.Service, *crypto.Identity) {
	id, err := loadIdentity(idFile)
	check(err)
	mb := drop.NewMailbox(carrier.NewFS(dropDir), id)
	return message.NewService(mb, message.NewRegistry()), id
}

func cmdSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	idFile := fs.String("id", "identity.json", "identity file")
	dropDir := fs.String("drop", "./drop", "carrier drop directory")
	toFile := fs.String("to", "", "recipient contact file")
	text := fs.String("text", "", "message text")
	fs.Parse(args)

	svc, _ := openService(*idFile, *dropDir)
	to, err := loadContact(*toFile)
	check(err)
	id, err := svc.Send(to, message.Text{Body: *text})
	check(err)
	fmt.Printf("sent msg %s to %s\n", hex.EncodeToString(id[:]), to.Fingerprint())
}

func cmdRecv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	idFile := fs.String("id", "identity.json", "identity file")
	dropDir := fs.String("drop", "./drop", "carrier drop directory")
	interval := fs.Duration("interval", 2*time.Second, "poll interval")
	once := fs.Bool("once", false, "poll once and exit")
	fs.Parse(args)

	id, err := loadIdentity(*idFile)
	check(err)
	reg := message.NewRegistry()
	reg.Register(message.TextHandler{OnText: func(from crypto.Contact, t message.Text) {
		fmt.Printf("[%s] %s\n", from.Fingerprint(), t.Body)
	}})
	svc := message.NewService(drop.NewMailbox(carrier.NewFS(*dropDir), id), reg)
	svc.AutoAck = false // we may not know senders' encryption keys

	if !*once {
		fmt.Println("listening; Ctrl-C to stop")
	}
	pollLoop(*interval, *once, func() { svc.Poll() })
}

func cmdSafePropose(args []string) {
	fs := flag.NewFlagSet("safe-propose", flag.ExitOnError)
	idFile := fs.String("id", "identity.json", "identity file")
	dropDir := fs.String("drop", "./drop", "carrier drop directory")
	toFile := fs.String("to", "", "co-signer contact file")
	wallet := fs.String("wallet", "", "proposer wallet private key (hex)")
	chain := fs.Uint64("chain", 1, "EVM chain id")
	safe := fs.String("safe", "", "Safe contract address")
	token := fs.String("token", "", "ERC-20 token address")
	dest := fs.String("dest", "", "recipient address")
	amount := fs.String("amount", "0", "amount in token base units")
	nonce := fs.Uint64("nonce", 0, "Safe nonce")
	fs.Parse(args)

	svc, _ := openService(*idFile, *dropDir)
	to, err := loadContact(*toFile)
	check(err)
	wkey, err := ethcrypto.HexToECDSA(*wallet)
	check(err)
	amt, ok := new(big.Int).SetString(*amount, 10)
	if !ok {
		fatal("bad -amount")
	}
	tx := cryptotx.NewStablecoinTransfer(*chain, common.HexToAddress(*safe),
		common.HexToAddress(*token), common.HexToAddress(*dest), amt, *nonce)
	signer, err := tx.SignWith(wkey)
	check(err)
	msgID, err := svc.Send(to, tx)
	check(err)
	fmt.Printf("proposed Safe tx\n  safeTxHash: %s\n  signed by:  %s\n  sent msg:   %s to %s\n",
		tx.Hash().Hex(), signer.Hex(), hex.EncodeToString(msgID[:]), to.Fingerprint())
}

func cmdSafeCosign(args []string) {
	fs := flag.NewFlagSet("safe-cosign", flag.ExitOnError)
	idFile := fs.String("id", "identity.json", "identity file")
	dropDir := fs.String("drop", "./drop", "carrier drop directory")
	wallet := fs.String("wallet", "", "co-signer wallet private key (hex)")
	threshold := fs.Int("threshold", 2, "required signatures")
	interval := fs.Duration("interval", 2*time.Second, "poll interval")
	rpc := fs.String("rpc", "", "EVM RPC URL (optional; submit when threshold met)")
	relayer := fs.String("relayer", "", "relayer wallet key for submission (hex)")
	once := fs.Bool("once", false, "poll once and exit")
	fs.Parse(args)

	id, err := loadIdentity(*idFile)
	check(err)
	wkey, err := ethcrypto.HexToECDSA(*wallet)
	check(err)
	mb := drop.NewMailbox(carrier.NewFS(*dropDir), id)
	reg := message.NewRegistry()
	reg.Register(cryptotx.Handler{OnSafeTx: func(from crypto.Contact, tx *cryptotx.SafeTx) {
		fmt.Printf("received Safe tx %s (%d sig) — VERIFY: to=%s value/data below\n",
			tx.Hash().Hex(), len(tx.Signatures), tx.To.Hex())
		signer, err := tx.SignWith(wkey)
		if err != nil {
			fmt.Println("sign error:", err)
			return
		}
		fmt.Printf("co-signed by %s; now %d/%d\n", signer.Hex(), len(tx.Signatures), *threshold)
		if !tx.Reached(*threshold) {
			fmt.Println("threshold not met; waiting for more signers")
			return
		}
		call := cryptotx.BuildExecCall(tx)
		fmt.Printf("THRESHOLD MET — execTransaction ready\n  to:   %s\n  data: 0x%s\n",
			call.To.Hex(), hex.EncodeToString(call.Data))
		if *rpc != "" && *relayer != "" {
			submit(*rpc, *relayer, tx)
		}
	}})
	svc := message.NewService(mb, reg)
	svc.AutoAck = false

	if !*once {
		fmt.Println("co-signer listening; Ctrl-C to stop")
	}
	pollLoop(*interval, *once, func() { svc.Poll() })
}

func submit(rpc, relayerHex string, tx *cryptotx.SafeTx) {
	client, err := ethclient.Dial(rpc)
	if err != nil {
		fmt.Println("rpc dial:", err)
		return
	}
	rk, err := ethcrypto.HexToECDSA(relayerHex)
	if err != nil {
		fmt.Println("relayer key:", err)
		return
	}
	h, err := cryptotx.Submit(context.Background(), client, rk, tx)
	if err != nil {
		fmt.Println("submit:", err)
		return
	}
	fmt.Printf("submitted: %s\n", h.Hex())
}

func pollLoop(interval time.Duration, once bool, poll func()) {
	poll()
	if once {
		return
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-sigc:
			return
		case <-t.C:
			poll()
		}
	}
}

func check(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
