package message

import "deaddrop/crypto"

// TextType is the payload type tag for plain text messages.
const TextType = "text"

// Text is a plain UTF-8 chat message.
type Text struct{ Body string }

func (Text) Type() string              { return TextType }
func (t Text) Encode() ([]byte, error) { return []byte(t.Body), nil }

// TextHandler decodes Text payloads and forwards them to OnText.
type TextHandler struct {
	OnText func(from crypto.Contact, t Text)
}

func (TextHandler) Type() string { return TextType }

func (TextHandler) Decode(data []byte) (Payload, error) {
	return Text{Body: string(data)}, nil
}

func (h TextHandler) Handle(from crypto.Contact, p Payload) error {
	if h.OnText != nil {
		h.OnText(from, p.(Text))
	}
	return nil
}
