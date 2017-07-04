package htlcswitch

import (
	"crypto/sha256"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcutil"
)

// Packet interface represent the switch packet.
type Packet interface {
	// Update returns the htlc update which packets carries with it.
	Update() lnwire.Message
}

// initPacket wraps the add update htlc and is needed to distinct the
// use request to make the payment. Packet carries additional information about
// first node in payment path.
type initPacket struct {
	// destNode is the first-hop destination of a local created HTLC add
	// message.
	destNode [btcec.PubKeyBytesLenCompressed]byte

	// htlc lnwire message type of which depends on switch request type.
	htlc *lnwire.UpdateAddHTLC
}

// newInitPacket creates htlc switch add packet which encapsulates the add htlc
// request and additional information for proper forwarding over htlc switch.
func newInitPacket(destNode [33]byte, htlc *lnwire.UpdateAddHTLC) *initPacket {
	return &initPacket{
		destNode: destNode,
		htlc:     htlc,
	}
}

// Update returns the htlc update which packets carries with it.
// NOTE: Part of the Packet interface.
func (p *initPacket) Update() lnwire.Message {
	return p.htlc
}

// addPacket wraps the add htlc update which traveling from one channel to
// another. Also carries additional data which is need for proper propagation.
type addPacket struct {
	// src is the source of this packet identified by the short channel ID
	// of the target link.
	src lnwire.ShortChannelID

	// dest is the destination of this packet identified by the short
	// channel ID of the target link.
	dest lnwire.ShortChannelID

	// htlc is an add htlc update which carried from one channel to
	// another.
	htlc *lnwire.UpdateAddHTLC

	// obfuscator is entity which is needed to make the obfuscation of the
	// onion failure, it is carried inside the packet from channel
	// link to the switch because we have to create onion error inside the
	// switch too, but we unable to restore obfuscator from the onion, because
	// on stage of forwarding onion inside payment belongs to the remote node.
	// TODO(andrew.shvv) revisit after refactoring the way of returning errors
	// inside the htlcswitch packet.
	obfuscator Obfuscator

	// senderPubKey the pubkey of the payment sender.
	// NOTE: Populated only on the last hop, only if it was sphinx payment,
	// and if sender sent this information.
	senderPubKey *btcec.PublicKey

	// paymentDescription the additional data which is carried from the payment
	// sender to payment receiver.
	// NOTE: Populated only on the last hop, only if it was sphinx payment,
	// and if sender sent this information.
	paymentDescription []byte
}

// newAddPacket creates htlc switch add packet which encapsulates the add htlc
// request and additional information for proper forwarding over htlc switch.
func newAddPacket(src, dest lnwire.ShortChannelID, htlc *lnwire.UpdateAddHTLC,
	obfuscator Obfuscator, pubKey *btcec.PublicKey, desc []byte) *addPacket {

	return &addPacket{
		dest:               dest,
		src:                src,
		htlc:               htlc,
		obfuscator:         obfuscator,
		senderPubKey:       pubKey,
		paymentDescription: desc,
	}
}

// Update returns the htlc update which packets carries with it.
// NOTE: Part of the Packet interface.
func (p *addPacket) Update() lnwire.Message {
	return p.htlc
}

// settlePacket wraps the settle htlc update which travels backward to the
// payment sender. Also carries additional information which is need for
// proper backward propagation.
type settlePacket struct {
	// src is the source of this packet identified by the short channel ID
	// of the target link.
	src lnwire.ShortChannelID

	// htlc lnwire message type of which depends on switch request type.
	htlc *lnwire.UpdateFufillHTLC

	// payHash is the payment hash of the HTLC which was modified by either
	// a settle or fail action.
	payHash [sha256.Size]byte

	// amount is the value of the HTLC that is being created or modified.
	amount btcutil.Amount
}

// Update returns the htlc update which packets carries with it.
// NOTE: Part of the Packet interface.
func (p *settlePacket) Update() lnwire.Message {
	return p.htlc
}

// newSettlePacket creates htlc switch ack/settle packet which encapsulates the
// settle htlc request which should be created and sent back by last hope in
// htlc path.
func newSettlePacket(src lnwire.ShortChannelID, htlc *lnwire.UpdateFufillHTLC,
	payHash [sha256.Size]byte, amount btcutil.Amount) *settlePacket {

	return &settlePacket{
		src:     src,
		payHash: payHash,
		htlc:    htlc,
		amount:  amount,
	}
}

// failPacket wraps the fail htlc update which travels backward to the
// payment sender. Also carries additional information which is need for
// proper backward propagation.
type failPacket struct {
	// src is the source of this packet identified by the short channel ID
	// of the target link.
	src lnwire.ShortChannelID

	// htlc lnwire message type of which depends on switch request type.
	htlc *lnwire.UpdateFailHTLC

	// payHash is the payment hash of the HTLC which was modified by either
	// a settle or fail action.
	payHash [sha256.Size]byte

	// amount is the value of the HTLC that is being created or modified.
	amount btcutil.Amount

	// isObfuscated is used in case if switch sent the packet to the link,
	// but error have occurred locally, in this case we shouldn't obfuscate
	// it again.
	// TODO(andrew.shvv) revisit after refactoring the way of returning errors
	// inside the htlcswitch packet.
	isObfuscated bool
}

// Update returns the htlc update which packets carries with it.
// NOTE: Part of the Packet interface.
func (p *failPacket) Update() lnwire.Message {
	return p.htlc
}

// newFailPacket creates htlc switch fail packet which encapsulates the fail
// htlc request which propagated back to the original hope who sent the htlc
// add request if something wrong happened on the path to the final
// destination.
func newFailPacket(src lnwire.ShortChannelID, htlc *lnwire.UpdateFailHTLC,
	payHash [sha256.Size]byte, amount btcutil.Amount, isObfuscated bool) *failPacket {
	return &failPacket{
		src:          src,
		payHash:      payHash,
		htlc:         htlc,
		amount:       amount,
		isObfuscated: isObfuscated,
	}
}
