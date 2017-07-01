package htlcswitch

import (
	"encoding/binary"
	"io"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcutil"
)

// NetworkHop indicates the blockchain network that is intended to be the next
// hop for a forwarded HTLC. The existnce of this field within the
// ForwardingInfo struct enables the ability for HTLC to cross chain-boundaries
// at will.
type NetworkHop uint8

const (
	// BitcoinHop denotes that an HTLC is to be forwarded along the Bitcoin
	// link with the specified short channel ID.
	BitcoinHop NetworkHop = iota

	// LitecoinHop denotes that an HTLC is to be forwarded along the
	// Litecoin link with the specified short channel ID.
	LitecoinHop
)

// String returns the string representation of the target NetworkHop.
func (c NetworkHop) String() string {
	switch c {
	case BitcoinHop:
		return "Bitcoin"
	case LitecoinHop:
		return "Litecoin"
	default:
		return "Kekcoin"
	}
}

var (
	// exitHop is a special "hop" which denotes that an incoming HTLC is
	// meant to pay finally to the receiving node.
	exitHop lnwire.ShortChannelID
)

// ForwardingInfo contains all the information that is necessary to forward and
// incoming HTLC to the next hop encoded within a valid HopIterator instance.
// Forwarding links are to use this information to authenticate the information
// received within the incoming HTLC, to ensure that the prior hop didn't
// tamper with the end-to-end routing information at all.
type ForwardingInfo struct {
	// Network is the target blockchain network that the HTLC will travel
	// over next.
	Network NetworkHop

	// NextHop is the channel ID of the next hop. The received HTLC should
	// be forwarded to this particular channel in order to continue the
	// end-to-end route.
	NextHop lnwire.ShortChannelID

	// AmountToForward is the amount that the receiving node should forward
	// to the next hop.
	AmountToForward btcutil.Amount

	// OutgoingCTLV is the specified value of the CTLV timelock to be used
	// in the outgoing HTLC.
	OutgoingCTLV uint32

	// E2EPayload is the blob of data, which sender wants to share with receiver.
	// The exact interpretation of the meaning of this data, should be defined
	// on the application layer.
	// NOTE: Populated only on the exit hop. And only if sender set the e2e
	// payload.
	E2EPayload [sphinx.E2EPayloadSize]byte

	// TODO(roasbeef): modify sphinx logic to not just discard the
	// remaining bytes, instead should include the rest as excess
}

// HopIterator is an interface that abstracts away the routing information
// included in HTLC's which includes the entirety of the payment path of an
// HTLC. This interface provides two basic method which carry out: how to
// interpret the forwarding information encoded within the HTLC packet, and hop
// to encode the forwarding information for the _next_ hop.
type HopIterator interface {
	// ForwardingInstructions returns the set of fields that detail exactly
	// _how_ this hop should forward the HTLC to the next hop.
	// Additionally, the information encoded within the returned
	// ForwardingInfo is to be used by each hop to authenticate the
	// information given to it by the prior hop.
	ForwardingInstructions() ForwardingInfo

	// EncodeNextHop encodes the onion packet destined for the next hop
	// into the passed io.Writer.
	EncodeNextHop(w io.Writer) error
}

// sphinxHopIterator is the Sphinx implementation of hop iterator which uses
// onion routing to encode the payment route  in such a way so that node might
// see only the next hop in the route..
type sphinxHopIterator struct {
	// nextPacket is the decoded onion packet for the _next_ hop.
	nextPacket *sphinx.OnionPacket

	// processedPacket is the outcome of processing an onion packet. It
	// includes the information required to properly forward the packet to
	// the next hop.
	processedPacket *sphinx.ProcessedPacket
}

// A compile time check to ensure sphinxHopIterator implements the HopIterator
// interface.
var _ HopIterator = (*sphinxHopIterator)(nil)

// Encode encodes iterator and writes it to the writer.
//
// NOTE: Part of the HopIterator interface.
func (r *sphinxHopIterator) EncodeNextHop(w io.Writer) error {
	return r.nextPacket.Encode(w)
}

// ForwardingInstructions returns the set of fields that detail exactly _how_
// this hop should forward the HTLC to the next hop.  Additionally, the
// information encoded within the returned ForwardingInfo is to be used by each
// hop to authenticate the information given to it by the prior hop.
//
// NOTE: Part of the HopIterator interface.
func (r *sphinxHopIterator) ForwardingInstructions() ForwardingInfo {
	fwdInst := r.processedPacket.ForwardingInstructions

	var nextHop lnwire.ShortChannelID
	switch r.processedPacket.Action {
	case sphinx.ExitNode:
		nextHop = exitHop
	case sphinx.MoreHops:
		s := binary.BigEndian.Uint64(fwdInst.NextAddress[:])
		nextHop = lnwire.NewShortChanIDFromInt(s)
	}

	return ForwardingInfo{
		Network:         BitcoinHop,
		NextHop:         nextHop,
		AmountToForward: btcutil.Amount(fwdInst.ForwardAmount),
		OutgoingCTLV:    fwdInst.OutgoingCltv,
		E2EPayload:      r.processedPacket.E2EPayload,
	}
}

// OnionProcessor is responsible for keeping all sphinx dependent parts inside
// and expose only decoding function. With such approach we give freedom for
// subsystems which wants to decode sphinx path to not be dependable from
// sphinx at all.
//
// NOTE: The reason for keeping decoder separated from hop iterator is too
// maintain the hop iterator abstraction. Without it the structures which using
// the hop iterator should contain sphinx router which makes their creations in
// tests dependent from the sphinx internal parts.
type OnionProcessor struct {
	router *sphinx.Router
}

// NewOnionProcessor creates new instance of decoder.
func NewOnionProcessor(router *sphinx.Router) *OnionProcessor {
	return &OnionProcessor{router}
}

// GetHopIterator attempts to decode a valid sphinx packet from the passed io.Reader
// instance using the rHash as the associated data when checking the relevant
// MACs during the decoding process.
func (p *OnionProcessor) GetHopIterator(r io.Reader, rHash []byte) (HopIterator,
	error) {
	// Before adding the new HTLC to the state machine, parse the onion
	// object in order to obtain the routing information.
	onionPkt := &sphinx.OnionPacket{}
	if err := onionPkt.Decode(r); err != nil {
		return nil, err
	}

	// Attempt to process the Sphinx packet. We include the payment hash of
	// the HTLC as it's authenticated within the Sphinx packet itself as
	// associated data in order to thwart attempts a replay attacks. In the
	// case of a replay, an attacker is *forced* to use the same payment
	// hash twice, thereby losing their money entirely.
	sphinxPacket, err := p.router.ProcessOnionPacket(onionPkt, rHash)
	if err != nil {
		return nil, errors.Errorf("unable to process onion pkt: "+
			"%v", err)
	}

	return &sphinxHopIterator{
		nextPacket:      sphinxPacket.NextPacket,
		processedPacket: sphinxPacket,
	}, nil
}

// GetOnionObfuscator takes the onion blob as input extract the shard secret
// and return the entity which is able to obfuscate failure data.
func (p *OnionProcessor) GetOnionObfuscator(r io.Reader) (Obfuscator, error) {
	// Before adding the new HTLC to the state machine, parse the
	// onion object in order to obtain the routing information.
	onionPkt := &sphinx.OnionPacket{}
	if err := onionPkt.Decode(r); err != nil {
		return nil, err
	}

	onionObfuscator, err := sphinx.NewOnionObfuscator(p.router,
		onionPkt.EphemeralKey)
	if err != nil {
		return nil, err
	}

	return &FailureObfuscator{
		OnionObfuscator: onionObfuscator,
	}, nil
}
