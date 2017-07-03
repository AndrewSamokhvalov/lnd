package htlcswitch

import (
	"reflect"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lnwire"
)

// TestWaitingQueueThreadSafety test the thread safety properties of the
// waiting queue, by executing methods in seprate goroutines which operates
// with the same data.
func TestWaitingQueueThreadSafety(t *testing.T) {
	t.Parallel()

	q := newWaitingQueue()

	a := make([]uint64, 1000)
	for i := 0; i < len(a); i++ {
		a[i] = uint64(i)
		q.consume(&initPacket{
			htlc: &lnwire.UpdateAddHTLC{ID: uint64(i)},
		})
	}

	var b []uint64
	for i := 0; i < len(a); i++ {
		q.release()

		select {
		case packet := <-q.pending:
			b = append(b, uint64(packet.Update().(*lnwire.UpdateAddHTLC).ID))

		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	}

	if !reflect.DeepEqual(b, a) {
		t.Fatal("wrong order of the objects")
	}
}
