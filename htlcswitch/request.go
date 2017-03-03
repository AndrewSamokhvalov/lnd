package htlcswitch

import (
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/roasbeef/btcd/wire"
)

// requestType represents the type of HTLC switch request type, and it is needed
// for compilation error in case if wrong type was specified.
type requestType uint8

const (
	// forwardAddRequest encapsulates the HTLC add request which should be
	// propagated to another channel over HTLC switch.
	forwardAddRequest requestType = iota

	// userAddRequest encapsulates the HTLC add request which made by user
	// and the state of which should be propagated back to user after HTLC
	// will be settled.
	userAddRequest

	// forwardSettleRequest encapsulates the settle HTLC request which
	// made by last hope and propagated back to the original hope which sent
	// the HTLC add request.
	forwardSettleRequest

	// failRequest encapsulates the cancel HTLC request which propagated
	// back to the original hope which sent the HTLC add request.
	failRequest
)

// Response...
type Response struct {
	// Err is an error channel which is used to notify user about
	// status of payment request is it was canceled or successfully
	// settled.
	Err chan error

	// Preimage...
	Preimage chan [32]byte
}

// newResponse..
func newResponse() *Response {
	return &Response{
		Err:      make(chan error, 1),
		Preimage: make(chan [32]byte, 1),
	}
}

// request...
type request struct {
	// rType is a type of switch request which is used to determine the
	// necessary behaviour. For example: If HTLC was settled - should we
	// send the notification over error channel or propagate it back
	// over HTLC switch?
	rType requestType

	// payHash payment hash of htlc request.
	payHash [32]byte

	// dest is the next peer in HTLC path.
	dest *routing.HopID

	// channelPoint channel point from which HTLC message came from.
	channelPoint *wire.OutPoint

	// htlc lnwire HTLC message type of which depends on switch request
	// type.
	htlc lnwire.Message

	// response...
	response *Response
}

// newUserAddRequest creates new switch request with userAddRequest type, for
// more information look at userAddRequest comments.
func newUserAddRequest(dest *routing.HopID,
	htlc *lnwire.UpdateAddHTLC) *request {
	return &request{
		rType:    userAddRequest,
		dest:     dest,
		htlc:     lnwire.Message(htlc),
		response: newResponse(),
	}
}

// newForwardAddRequest creates new switch request with forwardAddRequest type,
// for more information look at forwardAddRequest type comments.
// NOTE: the name "source" is considered in terms of htlc switch circuit.
func newForwardAddRequest(dest *routing.HopID, source *wire.OutPoint,
	htlc *lnwire.UpdateAddHTLC) *request {
	return &request{
		rType:        forwardAddRequest,
		dest:         dest,
		channelPoint: source,
		htlc:         lnwire.Message(htlc),
	}
}

// newForwardSettleRequest creates new switch request with forwardSettleRequest
// type, for more information look at forwardSettleRequest type comments.
// NOTE: the name "source" is considered from htlc switch POV.
func newForwardSettleRequest(destination *wire.OutPoint,
	htlc *lnwire.UpdateFufillHTLC) *request {
	return &request{
		rType:        forwardSettleRequest,
		channelPoint: destination,
		htlc:         lnwire.Message(htlc),
	}
}

// newFailRequest creates new switch request with failRequest type, for more
// information look at failRequest type comments.
// NOTE: the name "destination" is considered from htlc switch POV.
func newFailRequest(destination *wire.OutPoint, htlc *lnwire.UpdateFailHTLC,
	payHash [32]byte) *request {
	return &request{
		rType:        failRequest,
		channelPoint: destination,
		payHash:      payHash,
		htlc:         htlc,
	}
}
