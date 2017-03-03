package htlcswitch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/btcsuite/fastsha256"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"sync"
	"testing"
)

// + ------------------------------------------------------------------------- +
// | 				MockServer  				       |
// + ------------------------------------------------------------------------- +
type MockServer struct {
	t           *testing.T
	name        string
	messages    chan lnwire.Message
	quit        chan bool
	id          []byte
	htlcSwitch  *HTLCSwitch
	wg          sync.WaitGroup
	recordFuncs []func(lnwire.Message)
}

var _ Peer = (*MockServer)(nil)

func NewMockServer(t *testing.T, name string) *MockServer {
	return &MockServer{
		t:           t,
		id:          []byte(name),
		name:        name,
		messages:    make(chan lnwire.Message, 50),
		quit:        make(chan bool),
		htlcSwitch:  NewHTLCSwitch(),
		recordFuncs: make([]func(lnwire.Message), 0),
	}
}

func (s *MockServer) Start() error {
	if err := s.htlcSwitch.Start(); err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		for {
			select {
			case msg := <-s.messages:
				for _, f := range s.recordFuncs {
					f(msg)
				}


				if err := s.readHandler(msg); err != nil {
					s.t.Fatalf("%v server error: %v", s.name, err)
				}
			case <-s.quit:
				return
			}
		}
	}()

	return nil
}

// Record is used to set the function which will be triggered when new
// lnwire message was received.
func (s *MockServer) Record(f func(lnwire.Message)) {
	s.recordFuncs = append(s.recordFuncs, f)
}

func (s *MockServer) SendMessage(message lnwire.Message) error {
	select {
	case s.messages <- message:
	case <-s.quit:
	}

	return nil
}

func (s *MockServer) readHandler(message lnwire.Message) error {
	var targetChan wire.OutPoint

	switch msg := message.(type) {
	case *lnwire.UpdateAddHTLC:
		targetChan = msg.ChannelPoint
	case *lnwire.UpdateFufillHTLC:
		targetChan = msg.ChannelPoint
	case *lnwire.UpdateFailHTLC:
		targetChan = msg.ChannelPoint
	case *lnwire.RevokeAndAck:
		targetChan = msg.ChannelPoint
	case *lnwire.CommitSig:
		targetChan = msg.ChannelPoint
	default:
		return errors.New("unknown message type")
	}

	// Dispatch the commitment update message to the proper
	// htc manager dedicated to this channel.
	manager, err := s.htlcSwitch.Get(targetChan)
	if err != nil {
		return err
	}

	if err := manager.HandleMessage(message); err != nil {
		return err
	}

	return nil
}

func (p *MockServer) WipeChannel(*lnwallet.LightningChannel) error {
	return nil
}

func (p *MockServer) LocalChannelClose(*ChanClose) {
	return
}

func (p *MockServer) ID() [sha256.Size]byte {
	return [sha256.Size]byte{}
}

func (p *MockServer) PubKey() []byte {
	return p.id
}

func (s *MockServer) Disconnect() {
	s.t.Fatalf("server %v was disconnected", s.name)
}

func (s *MockServer) Stop() {
	close(s.quit)
}

func (s *MockServer) Wait() {
	s.wg.Wait()

	s.htlcSwitch.Stop()
}

// + ------------------------------------------------------------------------- +
// | 				MockHopIterator  			       |
// + ------------------------------------------------------------------------- +

// MockHopIterator represents the test version of hop iterator which instead
// of encrypting the path in onion blob just stores the path as a list of hops.
type MockHopIterator struct {
	hops []*routing.HopID
}

func NewMockHopIterator(hops ...*routing.HopID) *MockHopIterator {
	return &MockHopIterator{hops: hops}
}

func (r *MockHopIterator) Next() *routing.HopID {
	if len(r.hops) != 0 {
		next := r.hops[0]
		r.hops = r.hops[1:]
		return next
	}

	return nil
}

func (r *MockHopIterator) ToBytes() ([]byte, error) {
	var buf bytes.Buffer

	var hopLength [4]byte
	binary.BigEndian.PutUint32(hopLength[:], uint32(len(r.hops)))
	_, err := buf.Write(hopLength[:])
	if err != nil {
		return nil, err
	}

	for _, hop := range r.hops {
		_, err := buf.Write(hop[:])
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

var _ routing.HopIterator = (*MockHopIterator)(nil)

// + ------------------------------------------------------------------------- +
// | 				MockIteratorDecoder  			       |
// + ------------------------------------------------------------------------- +

// MockIteratorDecoder test version of hop iterator decoder which decodes the
// decodes the encoded array of hops.
type MockIteratorDecoder struct{}

func (p *MockIteratorDecoder) Decode(data [lnwire.OnionPacketSize]byte,
	meta []byte) (routing.HopIterator, error) {
	buf := bytes.NewBuffer(data[:])

	var b [4]byte
	_, err := buf.Read(b[:])
	if err != nil {
		return nil, err
	}
	hopLength := binary.BigEndian.Uint32(b[:])

	hops := make([]*routing.HopID, hopLength)
	for i := uint32(0); i < hopLength; i++ {
		var hop routing.HopID

		_, err := buf.Read(hop[:])
		if err != nil {
			return nil, err
		}

		hops[i] = &hop
	}

	return NewMockHopIterator(hops...), nil
}

// + ------------------------------------------------------------------------- +
// | 				MockArbiter 	 			       |
// + ------------------------------------------------------------------------- +
type MockArbiter struct{}

func (a *MockArbiter) SettleChannel(*wire.OutPoint) {

}

// + ------------------------------------------------------------------------- +
// | 				MockInvoiceRegistry 	 		       |
// + ------------------------------------------------------------------------- +
type MockInvoiceRegistry struct {
	invoices map[chainhash.Hash]*channeldb.Invoice
}

func NewRegistry() *MockInvoiceRegistry {
	return &MockInvoiceRegistry{
		invoices: make(map[chainhash.Hash]*channeldb.Invoice),
	}
}

func (i *MockInvoiceRegistry) LookupInvoice(rHash chainhash.Hash) (*channeldb.Invoice, error) {
	invoice, ok := i.invoices[rHash]
	if !ok {
		return nil, errors.New("can't find mock invoice")
	}

	return invoice, nil
}

func (i *MockInvoiceRegistry) SettleInvoice(rhash chainhash.Hash) error {
	invoice, err := i.LookupInvoice(rhash)
	if err != nil {
		return err
	}
	invoice.Terms.Settled = true
	return nil
}

func (i *MockInvoiceRegistry) AddInvoice(invoice *channeldb.Invoice) error {
	rhash := fastsha256.Sum256(invoice.Terms.PaymentPreimage[:])
	i.invoices[chainhash.Hash(rhash)] = invoice
	return nil
}

var _ InvoiceDatabase = (*MockInvoiceRegistry)(nil)

// + ------------------------------------------------------------------------- +
// | 				MockHtlcManager 	 		       |
// + ------------------------------------------------------------------------- +
type MockHtlcManager struct {
	ChanPoint *wire.OutPoint
	peer Peer
	Requests  chan *SwitchRequest
}

func NewMockHTLCManager(chanPoint *wire.OutPoint,
	peer Peer) *MockHtlcManager {
	return &MockHtlcManager{
		ChanPoint: chanPoint,
		Requests:  make(chan *SwitchRequest, 1),
		peer: peer,
	}
}

func (f *MockHtlcManager) HandleRequest(request *SwitchRequest) error {
	f.Requests <- request
	return nil
}

func (f *MockHtlcManager) HandleMessage(lnwire.Message) error {
	return nil
}

func (f *MockHtlcManager) Bandwidth() btcutil.Amount {
	return 99999999
}

func (f *MockHtlcManager) Capacity() btcutil.Amount {
	return 99999999
}

func (f *MockHtlcManager) SatSent() btcutil.Amount {
	return 0
}

func (f *MockHtlcManager) SatRecv() btcutil.Amount {
	return 0
}

func (f *MockHtlcManager) NumUpdates() uint64 {
	return 0
}

func (f *MockHtlcManager) ID() *wire.OutPoint {
	return f.ChanPoint
}

func (f *MockHtlcManager) Peer() Peer {
	return f.peer
}

func (f *MockHtlcManager) Start() error {
	return nil
}

func (f *MockHtlcManager) Stop() {}

func (f *MockHtlcManager) UpdateCommitTx() (bool, error) {
	return true, nil
}

var _ HTLCManager = (*MockHtlcManager)(nil)

// + ------------------------------------------------------------------------- +
// | 				MockSigner 	 		       	       |
// + ------------------------------------------------------------------------- +

type MockSigner struct {
	key *btcec.PrivateKey
}

func (m *MockSigner) SignOutputRaw(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) ([]byte, error) {
	amt := signDesc.Output.Value
	witnessScript := signDesc.WitnessScript
	privKey := m.key

	sig, err := txscript.RawTxInWitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, amt, witnessScript, txscript.SigHashAll, privKey)
	if err != nil {
		return nil, err
	}

	return sig[:len(sig)-1], nil
}

func (m *MockSigner) ComputeInputScript(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) (*lnwallet.InputScript, error) {

	witnessScript, err := txscript.WitnessScript(tx, signDesc.SigHashes,
		signDesc.InputIndex, signDesc.Output.Value, signDesc.Output.PkScript,
		txscript.SigHashAll, m.key, true)
	if err != nil {
		return nil, err
	}

	return &lnwallet.InputScript{
		Witness: witnessScript,
	}, nil
}

// + ------------------------------------------------------------------------- +
// | 				MockNotifier 	 		       	       |
// + ------------------------------------------------------------------------- +

type MockNotifier struct{}

func (m *MockNotifier) RegisterConfirmationsNtfn(txid *chainhash.Hash,
	numConfs uint32) (*chainntnfs.ConfirmationEvent, error) {
	return nil, nil
}
func (m *MockNotifier) RegisterBlockEpochNtfn() (*chainntnfs.BlockEpochEvent, error) {
	return nil, nil
}

func (m *MockNotifier) Start() error {
	return nil
}

func (m *MockNotifier) Stop() error {
	return nil
}
func (m *MockNotifier) RegisterSpendNtfn(outpoint *wire.OutPoint) (*chainntnfs.SpendEvent, error) {
	return &chainntnfs.SpendEvent{
		Spend: make(chan *chainntnfs.SpendDetail),
	}, nil
}
