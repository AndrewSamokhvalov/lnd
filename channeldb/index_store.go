package channeldb

import (
	"encoding/binary"

	"io"

	"bytes"

	"github.com/boltdb/bolt"
	"github.com/go-errors/errors"
)

var (
	// baseIndexBucketKey base byte string name of the index store.
	baseIndexBucketKey = []byte("indexstore")

	// ErrObjectsNotFound is returned if object haven't been found by
	// given index.
	ErrObjectsNotFound = errors.New("objects haven't been found")
)

// Storable represents the object which might be transformed in/from
// database specific representation. By using this interface we separate the
// specifics of the object representation from the bolddb logic.
type Storable interface {
	// Decode reads the data from the byte stream and initialize the
	// object with data.
	Decode(r io.Reader) error

	// Encode writes the internal representation of object in byte stream.
	Encode(w io.Writer) error
}

// IndexConfig defines the configuration for the index store. ALL elements
// within the configuration MUST be non-nil for the service to carry out its
// duties.
type IndexConfig struct {
	// GetInstance returns the specific object which might be stored.
	// Index store was designed in mind that it will be used with different
	// types of objects.
	GetInstance func() Storable
}

// IndexStore is the bold db storage where we assign the index to every object
// we store in increasing manner, by doing this we preserve the order of the
// objects and also give the ability to the user to quickly retrieve the object
// by using this index. By using index store subsystem might initialize the map
// of the object_id<->index during initialization and than use it for checking
// the existence of object without touching the db itself.
type IndexStore struct {
	// id is a unique slice of bytes identifying a storage.
	id  []byte
	db  *DB
	cfg IndexConfig
}

// NewIndexStore creates new instance of index storage.
func NewIndexStore(id []byte, db *DB, cfg IndexConfig) *IndexStore {
	return &IndexStore{
		id:  id,
		db:  db,
		cfg: cfg,
	}

}

// Add adds new storable object in the storage with preserving the
// order and returns the index of object within the store.
func (s *IndexStore) Add(obj Storable) (uint64, error) {
	var index uint64

	err := s.db.Batch(func(tx *bolt.Tx) error {
		var err error
		var b bytes.Buffer

		// Get or create the bucket.
		bucketKey := s.getBucketKey()
		bucket, err := tx.CreateBucketIfNotExists(bucketKey)
		if err != nil {
			return err
		}

		// Generate next index/sequence number.
		index, err = bucket.NextSequence()
		if err != nil {
			return err
		}
		indexBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(indexBytes, index)

		// Encode the objects and place it in the bucket.
		if err := obj.Encode(&b); err != nil {
			return err
		}

		return bucket.Put(indexBytes, b.Bytes())
	})

	return index, err
}

// RemoveWithReturn deletes objects by the given set of indexes and
// return the removed objects.
func (s *IndexStore) RemoveWithReturn(indexes ...uint64) ([]Storable, error) {
	var objects []Storable

	if err := s.remove(indexes, func(v []byte) error {
		// Retrieve object and add it to the array of objects.
		obj, err := s.retrieve(v)
		if err != nil {
			return err
		}
		objects = append(objects, obj)
		return nil
	}); err != nil {
		return nil, err
	}

	return objects, nil
}

// Remove removes the objects from storage by index that were assigned to
// it during its addition to the storage.
func (s *IndexStore) Remove(indexes ...uint64) error {
	return s.remove(indexes, nil)
}

// GetAll returns the sorted set of objects in the order they have been
// added originally and also the array of associated index to this
// objects within the store.
func (s *IndexStore) GetAll() ([]uint64, []Storable, error) {
	var objects []Storable
	var indexes []uint64

	if err := s.db.View(func(tx *bolt.Tx) error {
		bucketKey := s.getBucketKey()
		bucket := tx.Bucket(bucketKey)
		if bucket == nil {
			return ErrObjectsNotFound
		}

		// Iterate over objects buckets.
		return bucket.ForEach(func(k, v []byte) error {
			// Skip buckets fields.
			if v == nil {
				return nil
			}

			// Retrieve object and add it to the array of objects.
			obj, err := s.retrieve(v)
			if err != nil {
				return err
			}

			objects = append(objects, obj)
			indexes = append(indexes, binary.BigEndian.Uint64(k))
			return nil
		})
	}); err != nil {
		return nil, nil, err
	}

	// If bucket was haven't been created yet or just not contains any
	// objects.
	if len(objects) == 0 {
		return nil, nil, ErrObjectsNotFound
	}

	return indexes, objects, nil
}

// Get returns the object which corresponds to the given index.
func (s *IndexStore) Get(index uint64) (Storable, error) {
	var obj Storable

	err := s.db.View(func(tx *bolt.Tx) error {
		var err error

		bucketKey := s.getBucketKey()
		bucket := tx.Bucket(bucketKey)
		if bucket == nil {
			return ErrObjectsNotFound
		}

		// Generate next index/sequence number.
		indexBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(indexBytes, index)

		// Iterate over objects buckets.
		v := bucket.Get(indexBytes)
		if v == nil {
			return ErrObjectsNotFound
		}

		// Retrieve object and add it to the array of objects.
		obj, err = s.retrieve(v)
		if err != nil {
			return err
		}

		return nil

	})

	return obj, err
}

// getBucketKey generates the bucket boltd key by storage id and base
// bucket key.
func (s *IndexStore) getBucketKey() []byte {
	return append(baseIndexBucketKey[:], s.id[:]...)
}

// retrieve retrieves the object by the given byte array.
func (s *IndexStore) retrieve(v []byte) (Storable, error) {
	// Using get instance handler return an empty storable instance and
	// populate it with decoded data.
	r := bytes.NewReader(v)

	obj := s.cfg.GetInstance()
	if err := obj.Decode(r); err != nil {
		return nil, err
	}

	return obj, nil
}

// remove removes the objects which corresponds to the given indexes and
// invokes given callback.
func (s *IndexStore) remove(indexes []uint64, onRemove func(v []byte) error) error {
	return s.db.Batch(func(tx *bolt.Tx) error {
		// Get or create the top bucket.
		bucketKey := s.getBucketKey()
		bucket := tx.Bucket(bucketKey)
		if bucket == nil {
			return ErrObjectsNotFound
		}

		// Retrieve the objects indexes and remove them from top bucket.
		for _, index := range indexes {
			var key [8]byte
			binary.BigEndian.PutUint64(key[:], index)

			v := bucket.Get(key[:])
			if v == nil {
				return errors.New("object not found")
			}

			// Call on remove handler.
			if onRemove != nil {
				if err := onRemove(v); err != nil {
					return err
				}
			}

			if err := bucket.Delete(key[:]); err != nil {
				return err
			}
		}

		return nil
	})
}
