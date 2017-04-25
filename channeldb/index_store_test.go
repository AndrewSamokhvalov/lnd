package channeldb

import (
	"io"
	"testing"

	"encoding/binary"
)

type number struct {
	num uint16
}

func (n *number) Decode(r io.Reader) error {
	var data [2]byte
	if _, err := r.Read(data[:]); err != nil {
		return err
	}

	n.num = binary.BigEndian.Uint16(data[:])
	return nil
}

func (n *number) Encode(w io.Writer) error {
	var data [2]byte
	binary.BigEndian.PutUint16(data[:], n.num)

	if _, err := w.Write(data[:]); err != nil {
		return err
	}

	return nil
}

// Check that number implements storable interface.
var _ Storable = (*number)(nil)

// TestIndexStore tests add/get/remove functions of the index store and also
// check
func TestIndexStore(t *testing.T) {
	db, cleanup, err := makeTestDB()
	if err != nil {

	}
	defer cleanup()

	store := NewIndexStore([]byte("message"), db, IndexConfig{
		GetInstance: func() Storable {
			return &number{}
		},
	})

	if _, err := store.Add(&number{0}); err != nil {
		t.Fatalf("can't add message to index store: %v", err)
	}

	if _, err := store.Add(&number{1}); err != nil {
		t.Fatalf("can't add message to index store: %v", err)
	}

	indexes, messages, err := store.GetAll()
	if err != nil {
		t.Fatalf("can't get messages from index storage: %v", err)
	}

	if len(messages) != 2 {
		t.Fatal("wrong amount of messages")
	}

	if messages[0].(*number).num != 0 {
		t.Fatalf("wrong order")
	}

	if messages[1].(*number).num != 1 {
		t.Fatalf("wrong order")
	}

	if err := store.Remove(indexes...); err != nil {
		t.Fatalf("can't remove message from index store: %v", err)
	}

	_, messages, err = store.GetAll()
	if err != ErrObjectsNotFound {
		t.Fatalf("can't get messages from index storage: %v", err)
	}

	if len(messages) != 0 {
		t.Fatal("wrong amount of messages")
	}
}
