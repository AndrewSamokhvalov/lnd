package htlcswitch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/go-errors/errors"
	"github.com/roasbeef/btcd/wire"
	"sync"
)

// circuitKey uniquely identifies an active Sphinx (onion routing) circuit
// between two open channels. Currently, the rHash of the HTLC which created
// the circuit is used to uniquely identify each circuit.
type circuitKey [sha256.Size]byte

// String represent the circuit key in string format.
func (k *circuitKey) String() string {
	return hex.EncodeToString(k[:])
}

// paymentCircuit is used by HTLC switch service in order to determine
// backward path for settle/cancel HTLC messages. A payment circuit is created
// once a htlc manager forwards an HTLC add request. Channel points contained
// within this message is used to identify the source/destination HTLC managers.
//
// NOTE: In current implementation of HTLC switch, the payment circuit might be
// uniquely identified by payment hash but in future we implement the payment
// fragmentation which makes possible for number of payments to have
// identical payments hashes, but different source and destinations.
//
// For example if Alice(A) want to send 2BTC to Bob(B), then payment will be
// split on two parts and node N3 will have circuit with the same payment hash,
// and destination, but different source (N1,N2).
//
//	    	  1BTC    N1   1BTC
//    	      + --------- o --------- +
//      2BTC  |	                      |  2BTC
// A o ------ o N0	           N3 o ------ o B
//	      |		              |
// 	      + --------- o --------- +
//	         1BTC     N2   1BTC
//
type paymentCircuit struct {
	// PaymentHash used as unique identifier of payment (not payment
	// circuit).
	PaymentHash circuitKey

	// Src is the channel id from which add HTLC request is came from and
	// to which settle/cancel HTLC request will be returned back. Once the
	// switch forwards the settle message to the source the circuit is
	// considered to be completed.
	Src wire.OutPoint

	// Dest is the channel id to which we propagate the HTLC add request
	// and from which we are expecting to receive HTLC settle request back.
	Dest wire.OutPoint
}

// newPaymentCircuit creates new payment circuit instance.
func newPaymentCircuit(src, dest wire.OutPoint, key circuitKey) *paymentCircuit {
	return &paymentCircuit{
		Src:         src,
		Dest:        dest,
		PaymentHash: key,
	}
}

// isEqual checks the equality of two payment circuits.
func (a *paymentCircuit) IsEqual(b *paymentCircuit) bool {
	return bytes.Equal(a.PaymentHash[:], b.PaymentHash[:]) &&
		a.Src == b.Src &&
		a.Dest == b.Dest
}

// circuitMap is a thread safe, persistent storage of circuits. Each
// circuit key (payment hash) might have numbers of circuits corresponding to it
// because of future payment fragmentation, now every circuit might be uniquely
// identified by payment hash (1-1 mapping).
type circuitMap struct {
	mutex    sync.RWMutex
	circuits map[circuitKey][]*paymentCircuit
}

// newCircuitMap initialized circuit map with previously stored circuits and
// return circuit map instance.
func newCircuitMap() *circuitMap {
	m := &circuitMap{
		circuits: make(map[circuitKey][]*paymentCircuit),
	}

	return m
}

// add function add circuit in circuit map, and also save it in database in
// thread safe manner.
func (m *circuitMap) add(circuit *paymentCircuit) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.circuits[circuit.PaymentHash] = append(
		m.circuits[circuit.PaymentHash],
		circuit,
	)

	return nil
}

// remove function removes circuit from map and database in thread safe manner.
func (m *circuitMap) remove(key circuitKey, dest wire.OutPoint) (
	*paymentCircuit, error) {

	m.mutex.Lock()
	defer m.mutex.Unlock()

	circuits, ok := m.circuits[key]
	if ok {
		for i, circuit := range circuits {
			if circuit.Dest == dest {
				// Delete without preserving order
				// Google: Golang slice tricks
				circuits[i] = circuits[len(circuits)-1]
				circuits[len(circuits)-1] = nil
				m.circuits[key] = circuits[:len(circuits)-1]

				return circuit, nil
			}
		}
	}

	return nil, errors.Errorf("can't find circuit"+
		" for key %v and destination %v", key, dest.String())
}

// pending returns number of circuits which are waiting for to be completed
// (settle/cancel responses to be received)
func (m *circuitMap) pending() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	length := 0
	for _, circuits := range m.circuits {
		length += len(circuits)
	}

	return length
}
