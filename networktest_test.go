package main

import (
	"testing"

	"bytes"
	"crypto/sha256"

	"time"

	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
)

// TestBridgeConnectionStopHandler test the ability of bridge to capture the
// messages and the ability of stop handler to properly stop messages until
// they will be handled.
func TestBridgeConnectionStopHandler(t *testing.T) {
	// First, generate the Alice and Bob private keys.
	alicePriv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("can't generate alice priv key: %v", err)
	}
	bobPriv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("can't generate bob priv key: %v", err)
	}

	// Create connection bridge to which we should to connect later.
	handler := newStopHandler()
	bridge, err := newConnectionBridge(alicePriv, bobPriv, handler)
	if err != nil {
		t.Fatalf("can't create connection bridge: %v", err)
	}

	bridge.start()
	defer bridge.stop()

	// Connect Alice to bridge and return connection that will link as with
	// Bob over bridge (Eve).
	aliceConn, err := brontide.Dial(alicePriv, bridge.endpointForAlice())
	if err != nil {
		t.Fatalf("can't connect alice to bridge: %v", err)
	}
	defer aliceConn.Close()

	// Connect Bob to bridge and return connection that will link as with
	// Alice over bridge (Eve).
	bobConn, err := brontide.Dial(bobPriv, bridge.endpointForBob())
	if err != nil {
		t.Fatalf("can't connect bob to bridge: %v", err)
	}
	defer bobConn.Close()

	// Start goroutine which wait for bridge to be shut down and fatal
	// if there is an error.
	go func() {
		if err := bridge.waitForShutdown(); err != nil {
			t.Fatalf("bridge was shut down with error: %v", err)
		}
	}()

	// Generate  message and send it from Alice to Bob and wait it to be
	// intercepted.
	var (
		hash1, _   = chainhash.NewHash(bytes.Repeat([]byte("1"), 32))
		chanPoint1 = wire.NewOutPoint(hash1, 1)
		preimage1  = [sha256.Size]byte{1}

		hash2, _   = chainhash.NewHash(bytes.Repeat([]byte("2"), 32))
		chanPoint2 = wire.NewOutPoint(hash2, 12)
		preimage2  = [sha256.Size]byte{2}
	)

	msg1 := &lnwire.UpdateFufillHTLC{
		ChannelPoint:    *chanPoint1,
		ID:              1,
		PaymentPreimage: preimage1,
	}

	msg2 := &lnwire.UpdateFufillHTLC{
		ChannelPoint:    *chanPoint2,
		ID:              2,
		PaymentPreimage: preimage2,
	}

	// Set bridge in handle mode and wait for data to be received from
	// Alice. Send two messages without intercepting them thereby
	// stopping them from being retransmitted to Bob.
	bridge.startCapturing()

	n, err := lnwire.WriteMessage(aliceConn, msg1, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("can't send message alice->bridge->bob: %v", err)
	} else if n == 0 {
		t.Fatal("message wasn't written")
	}

	n, err = lnwire.WriteMessage(aliceConn, msg2, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("can't send message alice->bridge->bob: %v", err)
	} else if n == 0 {
		t.Fatal("message wasn't written")
	}

	n, err = lnwire.WriteMessage(aliceConn, msg2, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("can't send message alice->bridge->bob: %v", err)
	} else if n == 0 {
		t.Fatal("message wasn't written")
	}

	firstInterceptedMsg, err := handler.getCapturedMessage()
	if err != nil {
		t.Fatalf("can't read next intercepted message: %v", err)
	}

	n, firstBobMsg, _, err := lnwire.ReadMessage(bobConn, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("can't read message alice<-bridge<-bob: %v", err)
	} else if n == 0 {
		t.Fatal("message wasn't read")
	}

	if firstInterceptedMsg.(*lnwire.UpdateFufillHTLC).ID != 1 {
		t.Fatal("messages was intercepted in wrong order")
	}

	if firstBobMsg.Command() != firstInterceptedMsg.Command() {
		t.Fatalf("wrong message intercepted: %v", firstInterceptedMsg)
	}

	secondInterceptedMsg, err := handler.getCapturedMessage()
	if err != nil {
		t.Fatalf("can't read next intercepted message: %v", err)
	}

	n, secondBobMsg, _, err := lnwire.ReadMessage(bobConn, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("can't read message alice<-bridge<-bob: %v", err)
	} else if n == 0 {
		t.Fatal("message wasn't read")
	}

	if secondInterceptedMsg.(*lnwire.UpdateFufillHTLC).ID != 2 {
		t.Fatal("messages was intercepted in wrong order")
	}

	if secondBobMsg.Command() != secondInterceptedMsg.Command() {
		t.Fatalf("wrong message intercepted: %v", firstInterceptedMsg)
	}

	// Stop intercepting messages and check that remote side received
	// third message.
	bridge.stopCapturing()

	n, _, _, err = lnwire.ReadMessage(bobConn, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("can't read message alice<-bridge<-bob: %v", err)
	} else if n == 0 {
		t.Fatal("message wasn't read")
	}
}

// TestBridgeConnectionDynamicHandler tests ability of dynamic handler to
// skip/block messages between nodes.
func TestBridgeConnectionDynamicHandler(t *testing.T) {
	// First, generate the Alice and Bob private keys.
	alicePriv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("can't generate alice priv key: %v", err)
	}
	bobPriv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("can't generate bob priv key: %v", err)
	}

	// Initialise the handler that should skip all messages.
	handler := &dynamicHandler{}
	messages := make(chan lnwire.Message)
	handler.SetHandler(func(msg lnwire.Message) (bool, error) {
		messages <- msg
		return true, nil
	})

	// Create connection bridge to which Alice and Bob should connect
	// later.
	bridge, err := newConnectionBridge(alicePriv, bobPriv, handler)
	if err != nil {
		t.Fatalf("can't create connection bridge: %v", err)
	}

	bridge.start()
	defer bridge.stop()

	// Connect Alice to bridge and return connection that will link us with
	// Bob over bridge (Eve).
	aliceConn, err := brontide.Dial(alicePriv, bridge.endpointForAlice())
	if err != nil {
		t.Fatalf("can't connect alice to bridge: %v", err)
	}
	defer aliceConn.Close()

	// Connect Bob to bridge and return connection that will link us with
	// Alice over bridge (Eve).
	bobConn, err := brontide.Dial(bobPriv, bridge.endpointForBob())
	if err != nil {
		t.Fatalf("can't connect bob to bridge: %v", err)
	}
	defer bobConn.Close()

	// Start goroutine which wait for bridge to be shut down and fatal
	// if there is an error.
	go func() {
		if err := bridge.waitForShutdown(); err != nil {
			t.Fatalf("bridge was shut down with error: %v", err)
		}
	}()

	// Generate  message and send it from Alice to Bob and wait it to be
	// captured.
	var (
		hash, _   = chainhash.NewHash(bytes.Repeat([]byte("1"), 32))
		chanPoint = wire.NewOutPoint(hash, 1)
		preimage  = [sha256.Size]byte{1}
	)

	msg := &lnwire.UpdateFufillHTLC{
		ChannelPoint:    *chanPoint,
		ID:              1,
		PaymentPreimage: preimage,
	}

	// Set bridge in capture mode and wait messages to be received from
	// Alice.
	bridge.startCapturing()
	defer bridge.stopCapturing()

	// Send message from Alice to Bob.
	n, err := lnwire.WriteMessage(aliceConn, msg, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("can't send message alice->bridge->bob: %v", err)
	} else if n == 0 {
		t.Fatal("message wasn't written")
	}

	// Wait for message to be captured.
	<-messages

	// Check that remote side DIDN'T receive the message.
	done := make(chan bool)
	go func() {
		n, _, _, _ := lnwire.ReadMessage(bobConn, 0, wire.SimNet)
		if n != 0 {
			t.Fatal("message was read")
		}
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("message was received!")
	case <-time.After(100 * time.Millisecond):
	}
}
