package htlcswitch

import (
	"reflect"
	"testing"
	"time"

	"github.com/roasbeef/btcutil"
)

// TestWaitingQueueThreadSafety test the thread safety properties of the
// waiting queue, by executing methods in seprate goroutines which operates
// with the same data.
func TestWaitingQueueThreadSafety(t *testing.T) {
	q := newWaitingQueue()

	go func() {
		for {
			q.length()
		}
	}()

	go func() {
		for {
			q.release()
		}
	}()

	a := make([]btcutil.Amount, 1000)
	for i := 0; i < len(a); i++ {
		a[i] = btcutil.Amount(i)
		q.consume(&htlcPacket{amount: btcutil.Amount(i)})
	}

	var b []btcutil.Amount
	for i := 0; i < len(a); i++ {
		select {
		case packet := <-q.pending:
			b = append(b, packet.amount)

		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	}

	if !reflect.DeepEqual(b, a) {
		t.Fatal("wrong order of the objects")
	}
}
