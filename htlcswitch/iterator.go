package htlcswitch

import (
	"bytes"
	"encoding/hex"

	"io"

	"github.com/btcsuite/golangcrypto/ripemd160"
	"github.com/roasbeef/btcutil"
)

// hopID represents the id which is used by propagation subsystem in order to
// identify lightning network node.
// TODO(andrew.shvv) remove after switching to the using channel id.
type hopID [ripemd160.Size]byte

// newHopID creates new instance of hop form node public key.
func newHopID(pubKey []byte) hopID {
	var routeID hopID
	copy(routeID[:], btcutil.Hash160(pubKey))
	return routeID
}

// String returns string representation of hop id.
func (h hopID) String() string {
	return hex.EncodeToString(h[:])
}

// IsEqual checks does the two hop ids are equal.
func (h hopID) IsEqual(h2 hopID) bool {
	return bytes.Equal(h[:], h2[:])
}

// HopIterator interface represent the entity which is able to give route
// hops one by one. This interface is used to have an abstraction over the
// algorithm which we use to determine the next hope in htlc route.
type HopIterator interface {
	// Next returns next hop if exist and nil if route is ended.
	Next() *hopID

	// Encode encodes iterator and writes it to the writer.
	Encode(w io.Writer) error
}
