package htlcswitch

import (
	"bytes"
	"crypto/sha256"
	"github.com/btcsuite/fastsha256"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	"testing"
	"time"
)

var (
	hash1, _ = chainhash.NewHash(bytes.Repeat([]byte("a"), 32))
	hash2, _ = chainhash.NewHash(bytes.Repeat([]byte("b"), 32))

	chanPoint1 = wire.NewOutPoint(hash1, 0)
	chanPoint2 = wire.NewOutPoint(hash2, 0)
)

// TestHtlcSwitchForward checks the ability o htlc switch to forward add/settle
// requests.
func TestHtlcSwitchForward(t *testing.T) {
	var request *SwitchRequest

	alicePeer := NewMockServer(t, "alice")
	bobPeer := NewMockServer(t, "bob")

	aliceHltcManager := NewMockHTLCManager(chanPoint1, alicePeer)
	bobHtlcManager := NewMockHTLCManager(chanPoint2, bobPeer)

	htlcSwitch := NewHTLCSwitch()
	htlcSwitch.Start()
	htlcSwitch.Add(aliceHltcManager)
	htlcSwitch.Add(bobHtlcManager)

	// Create request which should be forwarder from alice htlc manager
	// to bob htlc mananger.
	preimage := [sha256.Size]byte{1}
	rhash := fastsha256.Sum256(preimage[:])
	request = NewForwardAddRequest(
		routing.NewHopID(bobHtlcManager.Peer().PubKey()),
		aliceHltcManager.ID(),
		&lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
		},
	)

	// Handle the request and checks that bob htlc manager received it.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bobHtlcManager.Requests:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to destination")
	}

	if htlcSwitch.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob htlc manager handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice htlc manager.
	request = NewForwardSettleRequest(
		bobHtlcManager.ID(),
		&lnwire.UpdateFufillHTLC{
			PaymentPreimage: preimage,
		},
	)

	// Handle the request and checks that payment circuit works properly.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceHltcManager.Requests:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to source")
	}

	if htlcSwitch.circuits.pending() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestHtlcSwitchCancel checks that if htlc was rejected we remove unused
// circuits.
func TestHtlcSwitchCancel(t *testing.T) {
	var request *SwitchRequest

	alicePeer := NewMockServer(t, "alice")
	bobPeer := NewMockServer(t, "bob")

	aliceHltcManager := NewMockHTLCManager(chanPoint1, alicePeer)
	bobHtlcManager := NewMockHTLCManager(chanPoint2, bobPeer)

	htlcSwitch := NewHTLCSwitch()
	htlcSwitch.Start()
	htlcSwitch.Add(aliceHltcManager)
	htlcSwitch.Add(bobHtlcManager)

	// Create request which should be forwarder from alice htlc manager
	// to bob htlc manager.
	preimage := [sha256.Size]byte{1}
	rhash := fastsha256.Sum256(preimage[:])
	request = NewForwardAddRequest(
		routing.NewHopID(bobHtlcManager.Peer().PubKey()),
		aliceHltcManager.ID(),
		&lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
		},
	)

	// Handle the request and checks that bob htlc manager received it.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bobHtlcManager.Requests:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to destination")
	}

	if htlcSwitch.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob htlc manager handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice htlc manager.
	request = NewCancelRequest(
		bobHtlcManager.ID(),
		&lnwire.UpdateFailHTLC{},
		rhash,
	)

	// Handle the request and checks that payment circuit works properly.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceHltcManager.Requests:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to source")
	}

	if htlcSwitch.circuits.pending() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestAddSamePayment tests that we send the payment with the same
// payment hash.
func TestAddSamePayment(t *testing.T) {
	var request *SwitchRequest

	alicePeer := NewMockServer(t, "alice")
	bobPeer := NewMockServer(t, "bob")

	aliceHltcManager := NewMockHTLCManager(chanPoint1, alicePeer)
	bobHtlcManager := NewMockHTLCManager(chanPoint2, bobPeer)

	htlcSwitch := NewHTLCSwitch()
	htlcSwitch.Start()
	htlcSwitch.Add(aliceHltcManager)
	htlcSwitch.Add(bobHtlcManager)

	// Create request which should be forwarder from alice htlc manager
	// to bob htlc manager.
	preimage := [sha256.Size]byte{1}
	rhash := fastsha256.Sum256(preimage[:])
	request = NewForwardAddRequest(
		routing.NewHopID(bobHtlcManager.Peer().PubKey()),
		aliceHltcManager.ID(),
		&lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
		},
	)

	// Handle the request and checks that bob htlc manager received it.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bobHtlcManager.Requests:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to destination")
	}

	if htlcSwitch.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Handle the request and checks that bob htlc manager received it.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	if htlcSwitch.circuits.pending() != 2 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob htlc manager handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice htlc manager.
	request = NewCancelRequest(
		bobHtlcManager.ID(),
		&lnwire.UpdateFailHTLC{},
		rhash,
	)

	// Handle the request and checks that payment circuit works properly.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceHltcManager.Requests:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to source")
	}

	if htlcSwitch.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Handle the request and checks that payment circuit works properly.
	if err := htlcSwitch.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceHltcManager.Requests:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to source")
	}

	if htlcSwitch.circuits.pending() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}
