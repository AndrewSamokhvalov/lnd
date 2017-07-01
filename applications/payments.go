package applications

import (
	"crypto/sha256"
	"io"

	"bytes"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lightning-onion"
	"github.com/roasbeef/btcd/btcec"
)

var (
	// ErrInsufficientE2EPayloadCapacity...
	ErrInsufficientE2EPayloadCapacity = errors.New("capacity of sphinx " +
		"payload is insufficient")
)

// E2EPayload...
type E2EPayload interface {
	Decode(io.Reader) error
	Encode(io.Writer) error
	Type() E2EPayloadType
}

// E2EPayloadType....
type E2EPayloadType uint8

const (
	// SphinxPaymentPayload...
	SphinxPaymentPayload E2EPayloadType = iota
)

const (
	// pubKeyFieldMask...
	pubKeyFieldMask uint8 = 2 ^ 0

	// descriptionFieldMask...
	descriptionFieldMask uint8 = 2 ^ 1
)

// SphinxPayment...
type SphinxPayment struct {
	// mask...
	mask [1]byte

	// PaymentPreimage...
	PaymentPreimage [sha256.Size]byte

	// PubKey...
	// NOTE: Optional field.
	PubKey *btcec.PublicKey

	// Description...
	// NOTE: Optional field.
	Description []byte
}

// ...
var _ E2EPayload = (*SphinxPayment)(nil)

// NewSphinxPayment...
func NewSphinxPayment(preimage [sha256.Size]byte) *SphinxPayment {
	return &SphinxPayment{
		PaymentPreimage: preimage,
	}
}

// SetDescription...
func (p *SphinxPayment) SetDescription(description []byte) {
	p.mask[0] = p.mask[0] | descriptionFieldMask
	p.Description = description
}

// SetPubKey...
func (p *SphinxPayment) SetPubKey(pubKey *btcec.PublicKey) {
	p.mask[0] = p.mask[0] | pubKeyFieldMask
	p.PubKey = pubKey
}

// WithDescription...
func (p *SphinxPayment) WithDescription() bool {
	return (p.mask[0] & descriptionFieldMask) != 0
}

// WithPubKey...
func (p *SphinxPayment) WithPubKey() bool {
	return (p.mask[0] & pubKeyFieldMask) != 0
}

// Decode...
// NOTE: Part of the E2EPayload interface.
func (p *SphinxPayment) Decode(r io.Reader) error {
	if _, err := r.Read(p.mask[:]); err != nil {
		return err
	}

	if _, err := r.Read(p.PaymentPreimage[:]); err != nil {
		return err
	}

	if p.WithPubKey() {
		var pubKey [btcec.PubKeyBytesLenCompressed]byte
		if _, err := r.Read(pubKey[:]); err != nil {
			return err
		}

		key, err := btcec.ParsePubKey(pubKey[:], btcec.S256())
		if err != nil {
			return err
		}
		p.PubKey = key
	}

	if p.WithDescription() {
		var descriptionLength [1]byte
		if _, err := r.Read(descriptionLength[:]); err != nil {
			return err
		}

		p.Description = make([]byte, descriptionLength[0])
		if _, err := r.Read(p.Description[:]); err != nil {
			return err
		}
	}

	return nil
}

// Encode...
// NOTE: Part of the E2EPayload interface.
func (p *SphinxPayment) Encode(w io.Writer) error {
	if _, err := w.Write(p.mask[:]); err != nil {
		return err
	}

	if _, err := w.Write(p.PaymentPreimage[:]); err != nil {
		return err
	}

	if p.WithPubKey() {
		if _, err := w.Write(p.PubKey.SerializeCompressed()); err != nil {
			return err
		}
	}

	if p.WithDescription() {
		if _, err := w.Write([]byte{uint8(len(p.Description))}); err !=
			nil {
			return err
		}

		if _, err := w.Write(p.Description); err != nil {
			return err
		}
	}

	return nil
}

// Type...
// NOTE: Part of the E2EPayload interface.
func (*SphinxPayment) Type() E2EPayloadType {
	return SphinxPaymentPayload
}

// makeEmtpyE2EPayload...
func makeEmtpyE2EPayload(t E2EPayloadType) (E2EPayload, error) {
	switch t {
	case SphinxPaymentPayload:
		return &SphinxPayment{}, nil
	}

	return nil, errors.New("unknown e2e payload type")
}

// DecodeE2EPayload...
func DecodeE2EPayload(r io.Reader) (E2EPayload, error) {
	var payloadType [1]byte
	if _, err := r.Read(payloadType[:]); err != nil {
		return nil, err
	}

	payload, err := makeEmtpyE2EPayload(E2EPayloadType(payloadType[0]))
	if err != nil {
		return nil, err
	}

	if err := payload.Decode(r); err != nil {
		return nil, err
	}

	return payload, nil
}

// EncodeE2EPayload...
func EncodeE2EPayload(payload E2EPayload, w io.Writer) error {
	var payloadBuffer bytes.Buffer

	if _, err := payloadBuffer.Write([]byte{uint8(payload.Type())}); err != nil {
		return err
	}

	if err := payload.Encode(&payloadBuffer); err != nil {
		return err
	}

	paddingLength := sphinx.E2EPayloadSize - len(payloadBuffer.Bytes())
	if paddingLength < 0 {
		return ErrInsufficientE2EPayloadCapacity
	}
	padding := make([]byte, paddingLength)

	if _, err := payloadBuffer.Write(padding); err != nil {
		return err
	}

	_, err := w.Write(payloadBuffer.Bytes())
	return err
}
