package htlcswitch

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/btcsuite/fastsha256"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
)

var (
	hash1, _ = chainhash.NewHash(bytes.Repeat([]byte("a"), 32))
	hash2, _ = chainhash.NewHash(bytes.Repeat([]byte("b"), 32))

	chanPoint1 = wire.NewOutPoint(hash1, 0)
	chanPoint2 = wire.NewOutPoint(hash2, 0)

	chanID1 = lnwire.NewChanIDFromOutPoint(chanPoint1)
	chanID2 = lnwire.NewChanIDFromOutPoint(chanPoint2)
)

// TestSwitchForward checks the ability o htlc switch to Forward add/settle
// requests.
func TestSwitchForward(t *testing.T) {
	var packet *htlcPacket

	alicePeer := newMockServer(t, "alice")
	bobPeer := newMockServer(t, "bob")

	aliceChannelLink := newMockChannelLink(chanID1, alicePeer)
	bobChannelLink := newMockChannelLink(chanID2, bobPeer)

	s := New(Config{})
	s.Start()
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarder from alice channel
	// link to bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := fastsha256.Sum256(preimage[:])
	packet = newAddPacket(
		aliceChannelLink.ChanID(),
		newHopID(bobChannelLink.Peer().PubKey()),
		&lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
		},
	)

	// Handle the request and checks that bob channel link received it.
	if err := s.Forward(packet); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bobChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to destination")
	}

	if s.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob link handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice link.
	packet = newSettlePacket(
		bobChannelLink.ChanID(),
		&lnwire.UpdateFufillHTLC{
			PaymentPreimage: preimage,
		},
		rhash,
	)

	// Handle the request and checks that payment circuit works properly.
	if err := s.Forward(packet); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to channelPoint")
	}

	if s.circuits.pending() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestSwitchCancel checks that if htlc was rejected we remove unused
// circuits.
func TestSwitchCancel(t *testing.T) {
	var request *htlcPacket

	alicePeer := newMockServer(t, "alice")
	bobPeer := newMockServer(t, "bob")

	aliceChannelLink := newMockChannelLink(chanID1, alicePeer)
	bobChannelLink := newMockChannelLink(chanID2, bobPeer)

	s := New(Config{})
	s.Start()
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarder from alice channel link
	// to bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := fastsha256.Sum256(preimage[:])
	request = newAddPacket(
		aliceChannelLink.ChanID(),
		newHopID(bobChannelLink.Peer().PubKey()),
		&lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
		},
	)

	// Handle the request and checks that bob channel link received it.
	if err := s.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bobChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to destination")
	}

	if s.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob channel link handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice channel link.
	request = newFailPacket(
		bobChannelLink.ChanID(),
		&lnwire.UpdateFailHTLC{},
		rhash,
	)

	// Handle the request and checks that payment circuit works properly.
	if err := s.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to channelPoint")
	}

	if s.circuits.pending() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestSwitchAddSamePayment tests that we send the payment with the same
// payment hash.
func TestSwitchAddSamePayment(t *testing.T) {
	var request *htlcPacket

	alicePeer := newMockServer(t, "alice")
	bobPeer := newMockServer(t, "bob")

	aliceChannelLink := newMockChannelLink(chanID1, alicePeer)
	bobChannelLink := newMockChannelLink(chanID2, bobPeer)

	s := New(Config{})
	s.Start()
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add alice link: %v", err)
	}
	if err := s.AddLink(bobChannelLink); err != nil {
		t.Fatalf("unable to add bob link: %v", err)
	}

	// Create request which should be forwarder from alice channel link
	// to bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := fastsha256.Sum256(preimage[:])
	request = newAddPacket(
		aliceChannelLink.ChanID(),
		newHopID(bobChannelLink.Peer().PubKey()),
		&lnwire.UpdateAddHTLC{
			PaymentHash: rhash,
		},
	)

	// Handle the request and checks that bob channel link received it.
	if err := s.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bobChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to destination")
	}

	if s.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Handle the request and checks that bob channel link received it.
	if err := s.Forward(request); err != nil {
		t.Fatal(err)
	}

	if s.circuits.pending() != 2 {
		t.Fatal("wrong amount of circuits")
	}

	// Create settle request pretending that bob channel link handled
	// the add htlc request and sent the htlc settle request back. This
	// request should be forwarder back to alice channel link.
	request = newFailPacket(
		bobChannelLink.ChanID(),
		&lnwire.UpdateFailHTLC{},
		rhash,
	)

	// Handle the request and checks that payment circuit works properly.
	if err := s.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to channelPoint")
	}

	if s.circuits.pending() != 1 {
		t.Fatal("wrong amount of circuits")
	}

	// Handle the request and checks that payment circuit works properly.
	if err := s.Forward(request); err != nil {
		t.Fatal(err)
	}

	select {
	case <-aliceChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to channelPoint")
	}

	if s.circuits.pending() != 0 {
		t.Fatal("wrong amount of circuits")
	}
}

// TestSwitchSendPayment tests ability of htlc switch to respond to the
// users when response is came back from channel link.
func TestSwitchSendPayment(t *testing.T) {
	alicePeer := newMockServer(t, "alice")
	aliceChannelLink := newMockChannelLink(chanID1, alicePeer)

	s := New(Config{})
	s.Start()
	if err := s.AddLink(aliceChannelLink); err != nil {
		t.Fatalf("unable to add link: %v", err)
	}

	// Create request which should be forwarder from alice channel link
	// to bob channel link.
	preimage := [sha256.Size]byte{1}
	rhash := fastsha256.Sum256(preimage[:])
	update := &lnwire.UpdateAddHTLC{
		PaymentHash: rhash,
		ID:          1,
	}

	// Handle the request and checks that bob channel link received it.
	preimageChan, errChan := s.SendUpdate(aliceChannelLink.Peer().PubKey(),
		update)

	select {
	case <-aliceChannelLink.packets:
		break
	case <-time.After(time.Second):
		t.Fatal("request was not propogated to destination")
	}

	if len(s.pendingPayments) != 1 {
		t.Fatal("wrong amount of pending payments")
	}

	if s.circuits.pending() != 0 {
		t.Fatal("wrong amount of circuits")
	}

	// Create fail request pretending that bob channel link handled
	// the add htlc request with error  and sent the htlc fail request
	// back. This request should be forwarder back to alice channel link.
	packet := newFailPacket(aliceChannelLink.ChanID(),
		&lnwire.UpdateFailHTLC{
			Reason: []byte{byte(lnwire.IncorrectValue)},
			ID:     1,
		},
		rhash)

	if err := s.Forward(packet); err != nil {
		t.Fatalf("can't forward htlc packet: %v", err)
	}

	select {
	case err := <-errChan:
		select {
		case <-preimageChan:
		case <-time.After(time.Millisecond):
			t.Fatal("preimage wasn't received")
		}

		if err.Error() != errors.New(lnwire.IncorrectValue).Error() {
			t.Fatal("err wasn't received")
		}
	case <-time.After(time.Second):
		t.Fatal("err wasn't received")
	}

	if len(s.pendingPayments) != 0 {
		t.Fatal("wrong amount of pending payments")
	}
}