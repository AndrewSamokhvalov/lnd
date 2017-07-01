package applications

import (
	"crypto/sha256"
	"testing"

	"bytes"

	"reflect"

	"github.com/lightningnetwork/lightning-onion"
	"github.com/roasbeef/btcd/btcec"
)

func TestSphinxPaymentDecodeEncode(t *testing.T) {
	_, testPubKey := btcec.PrivKeyFromBytes(btcec.S256(), []byte("kek"))

	var preimage [sha256.Size]byte
	preimage[0] = 1

	payment := NewSphinxPayment(preimage)
	payment.SetPubKey(testPubKey)
	payment.SetDescription([]byte("buy covfefe"))

	var b bytes.Buffer
	if err := EncodeE2EPayload(payment, &b); err != nil {
		t.Fatalf("unabel to encode sphinx payment: %v", err)
	}

	if len(b.Bytes()) != sphinx.E2EPayloadSize {
		t.Fatal("wrong payload size")
	}

	payment2, err := DecodeE2EPayload(&b)
	if err != nil {
		t.Fatalf("unabel to decode sphinx payment: %v", err)
	}

	if !reflect.DeepEqual(payment, payment2) {
		t.Fatalf("payments aren't equal")
	}
}
