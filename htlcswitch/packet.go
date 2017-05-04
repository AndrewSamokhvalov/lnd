package htlcswitch

import (
	"crypto/sha256"

	"github.com/lightningnetwork/lnd/lnwire"
)

// htlcPacket is a wrapper around htlc lnwire update, which adds additional
// information which is needed by this package.
type htlcPacket struct {
	// payHash payment hash of htlc request.
	// NOTE: This fields is initialized only in settle and fail packets.
	payHash [sha256.Size]byte

	// dest is the next channel to which this update will be applied.
	// TODO(andrew.shvv) use short channel id instead.
	dest hopID

	// src is a previous channel to which htlc was applied.
	// TODO(andrew.shvv) use short channel id instead.
	src lnwire.ChannelID

	// htlc lnwire message type of which depends on switch request type.
	htlc lnwire.Message
}

// newInitPacket creates htlc switch add packet which encapsulates the
// add htlc request and additional information for proper forwarding over
// htlc switch.
func newInitPacket(dest hopID, htlc *lnwire.UpdateAddHTLC) *htlcPacket {
	return &htlcPacket{
		dest: dest,
		htlc: htlc,
	}
}

// newAddPacket creates htlc switch add packet which encapsulates the
// add htlc request and additional information for proper forwarding over
// htlc switch.
func newAddPacket(src lnwire.ChannelID, dest hopID,
	htlc *lnwire.UpdateAddHTLC) *htlcPacket {
	return &htlcPacket{
		dest: dest,
		src:  src,
		htlc: htlc,
	}
}

// newSettlePacket creates htlc switch ack/settle packet which encapsulates the
// settle htlc request which should be created and sent back by last hope in
// htlc path.
func newSettlePacket(src lnwire.ChannelID, htlc *lnwire.UpdateFufillHTLC,
	payHash [sha256.Size]byte) *htlcPacket {
	return &htlcPacket{
		src:     src,
		payHash: payHash,
		htlc:    htlc,
	}
}

// newFailPacket creates htlc switch fail packet which encapsulates the fail
// htlc request which propagated back to the original hope who sent the htlc
// add request if something wrong happened on the path to the final destination.
func newFailPacket(src lnwire.ChannelID, htlc *lnwire.UpdateFailHTLC,
	payHash [sha256.Size]byte) *htlcPacket {
	return &htlcPacket{
		src:     src,
		payHash: payHash,
		htlc:    htlc,
	}
}
