// Command aboxtui is a simple terminal UI for DeadDrop: a 1:1 secure chat over
// a carrier-backed drop, with live receive and an in-TUI Safe (EVM) co-sign
// action. It is a thin front-end over the same layers as the abox CLI.
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"deaddrop/carrier"
	"deaddrop/crypto"
	"deaddrop/drop"
	"deaddrop/keyfile"
	"deaddrop/message"
	"deaddrop/message/cryptotx"
)

func main() {
	idFile := flag.String("id", "identity.json", "identity file")
	dropDir := flag.String("drop", "./drop", "carrier drop directory")
	toFile := flag.String("to", "", "peer contact file")
	walletHex := flag.String("wallet", "", "EVM wallet key (hex) for Safe co-signing (optional)")
	threshold := flag.Int("threshold", 2, "Safe signature threshold")
	interval := flag.Duration("interval", 2*time.Second, "poll interval")
	flag.Parse()

	id, err := keyfile.LoadIdentity(*idFile)
	must(err)
	peer, err := keyfile.LoadContact(*toFile)
	must(err)

	var wkey *ecdsa.PrivateKey
	if *walletHex != "" {
		wkey, err = ethcrypto.HexToECDSA(*walletHex)
		must(err)
	}

	mb := drop.NewMailbox(carrier.NewFS(*dropDir), id)
	mb.AddContact(peer) // so acks/replies are addressable and From resolves fully

	m := newModel(mb, id, peer, wkey, *threshold, *interval)
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// --- messages ---

type polledMsg struct {
	ins []drop.Inbound
	err error
}
type tickMsg struct{}

// --- model ---

type model struct {
	mb        *drop.Mailbox
	peer      crypto.Contact
	meFP      string
	peerFP    string
	wallet    *ecdsa.PrivateKey
	threshold int
	interval  time.Duration

	vp      viewport.Model
	input   textinput.Model
	log     []string
	pending *cryptotx.SafeTx
	ready   bool
	w, h    int
}

func newModel(mb *drop.Mailbox, id *crypto.Identity, peer crypto.Contact, wallet *ecdsa.PrivateKey, threshold int, interval time.Duration) model {
	ti := textinput.New()
	ti.Placeholder = "type a message, Enter to send"
	ti.Focus()
	ti.CharLimit = 4096
	return model{
		mb: mb, peer: peer,
		meFP:   id.Contact().Fingerprint(),
		peerFP: peer.Fingerprint(),
		wallet: wallet, threshold: threshold, interval: interval,
		input: ti,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, m.poll())
}

func (m model) poll() tea.Cmd {
	mb := m.mb
	return func() tea.Msg {
		ins, err := mb.Receive()
		return polledMsg{ins: ins, err: err}
	}
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model) appendf(format string, a ...any) {
	m.log = append(m.log, fmt.Sprintf(format, a...))
	if m.ready {
		m.vp.SetContent(strings.Join(m.log, "\n"))
		m.vp.GotoBottom()
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		headerH, footerH := 2, 2
		if !m.ready {
			m.vp = viewport.New(msg.Width, msg.Height-headerH-footerH)
			m.ready = true
			m.vp.SetContent(strings.Join(m.log, "\n"))
		} else {
			m.vp.Width = msg.Width
			m.vp.Height = msg.Height - headerH - footerH
		}
		m.input.Width = msg.Width - 4

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "enter":
			body := strings.TrimSpace(m.input.Value())
			if body != "" {
				if _, err := m.mb.Send(m.peer, message.TextType, []byte(body)); err != nil {
					m.appendf("send error: %v", err)
				} else {
					m.appendf("→ %s", body)
				}
				m.input.SetValue("")
			}
		case "ctrl+g":
			m.cosign()
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			cmds = append(cmds, cmd)
		}

	case polledMsg:
		if msg.err != nil {
			m.appendf("poll error: %v", msg.err)
		} else {
			for _, in := range msg.ins {
				m.handle(in)
				_ = m.mb.Ack(in)
			}
		}
		cmds = append(cmds, tick(m.interval))

	case tickMsg:
		cmds = append(cmds, m.poll())
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)
	if m.ready {
		m.vp, cmd = m.vp.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}

// handle decodes one inbound message into the log / pending state.
func (m *model) handle(in drop.Inbound) {
	switch in.Type {
	case message.TextType:
		m.appendf("← %s", string(in.Payload))
	case cryptotx.SafeTxType:
		var tx cryptotx.SafeTx
		if err := json.Unmarshal(in.Payload, &tx); err != nil {
			m.appendf("[safe-tx] decode error: %v", err)
			return
		}
		if _, err := tx.VerifyOwners(); err != nil {
			m.appendf("[safe-tx] REJECTED (bad signature): %v", err)
			return
		}
		m.pending = &tx
		m.appendf("[safe-tx] %s… %d/%d sigs — verify, then Ctrl-G to co-sign",
			tx.Hash().Hex()[:18], len(tx.Signatures), m.threshold)
		m.appendf("          to=%s data=0x%s", tx.To.Hex(), short(hex.EncodeToString(tx.Data)))
	default:
		m.appendf("[%s] (unhandled type)", in.Type)
	}
}

func (m *model) cosign() {
	if m.pending == nil {
		m.appendf("no pending Safe tx to co-sign")
		return
	}
	if m.wallet == nil {
		m.appendf("no -wallet configured; cannot co-sign")
		return
	}
	signer, err := m.pending.SignWith(m.wallet)
	if err != nil {
		m.appendf("co-sign error: %v", err)
		return
	}
	m.appendf("co-signed by %s (%d sigs)", signer.Hex(), len(m.pending.Signatures))
	if m.pending.Reached(m.threshold) {
		call := cryptotx.BuildExecCall(m.pending)
		m.appendf("THRESHOLD MET — execTransaction to %s", call.To.Hex())
		m.appendf("calldata 0x%s", short(hex.EncodeToString(call.Data)))
		m.pending = nil
		return
	}
	if _, err := m.mb.Send(m.peer, cryptotx.SafeTxType, mustEncode(m.pending)); err != nil {
		m.appendf("forward error: %v", err)
		return
	}
	m.appendf("sent partially-signed tx back to %s", m.peerFP)
}

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	helpStyle   = lipgloss.NewStyle().Faint(true)
)

func (m model) View() string {
	if !m.ready {
		return "starting…"
	}
	header := headerStyle.Render(fmt.Sprintf("DeadDrop  me:%s  ↔  peer:%s", m.meFP, m.peerFP))
	help := helpStyle.Render("Enter send · Ctrl-G co-sign Safe tx · Ctrl-C quit")
	return fmt.Sprintf("%s\n%s\n%s\n%s", header, m.vp.View(), m.input.View(), help)
}

func short(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

func mustEncode(tx *cryptotx.SafeTx) []byte {
	b, _ := tx.Encode()
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
