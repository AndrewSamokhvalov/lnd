package htlcswitch

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"

	"encoding/binary"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
	"fmt"
)

// InvoiceDatabase is an interface which represents the system which may
// search and settle invoices.
// TODO(andrew.shvv) should be moved in other place.
type InvoiceDatabase interface {
	// AddInvoice...
	AddInvoice(*channeldb.Invoice) error

	// LookupInvoice...
	LookupInvoice(chainhash.Hash) (*channeldb.Invoice, error)

	// SettleInvoice...
	SettleInvoice(chainhash.Hash) error
}

// Peer is an interface which represents the remote lightning node inside our
// system.
// TODO(andrew.shvv) should be moved in other place.
type Peer interface {
	// SendMessage sends message to current peer.
	SendMessage(lnwire.Message) error

	// LocalChannelClose...
	LocalChannelClose(*ChanClose)

	// WipeChannel removes the passed channel from all indexes associated
	// with the peer, and deletes the channel from the database.
	WipeChannel(*lnwallet.LightningChannel) error

	// ID is a lightning network peer id.
	ID() [sha256.Size]byte

	// PubKey...
	PubKey() []byte

	// Disconnect disconnects peer if we have error which we can;t
	// properly handle.
	Disconnect()
}

const (
	// updateDelay is used to initialize update commitment tx timer.
	updateDelay = 30 * time.Millisecond
)

// HTLCManager is an interface which represents the subsystem for managing
// the incoming HTLC requests, applying the changes to the channel, and also
// propagating the HTLCs to HTLC switch if needed.
type HTLCManager interface {
	// HandleRequest handles the switch requests which forwarded to us
	// from another peer.
	HandleRequest(*request) error

	// HandleMessage handles the htlc requests which sent to us from remote
	// peer.
	HandleMessage(lnwire.Message) error

	// Bandwidth return the amount of satohis which this HTLC manager can
	// work with at this time.
	Bandwidth() btcutil.Amount

	// SatSent returns the amount of satoshis which was successfully sent
	// and settled in channel by this manager.
	SatSent() btcutil.Amount

	// SatRecv returns the amount of satoshi which was successfully
	// received and settled in channel by this manager.
	SatRecv() btcutil.Amount

	// NumUpdates return the number of updates which was applied to
	// managed the channel.
	NumUpdates() uint64

	// ID return the id of the managed channel.
	ID() *wire.OutPoint

	// Peer...
	Peer() Peer

	// Start is used to start the HTLC manager: receive incoming requests,
	// handle the channel notification, and also print some statistics.
	Start() error
	Stop()
}

// handleMessageCommand encapsulates peer HTLC message and adds error channel to
// receive Err from message handler.
type handleMessageCommand struct {
	message lnwire.Message
	err     chan error
}

// forwardRequest encapsulates switch request and adds error channel to
// receive Err from request handler.
type requestForward struct {
	req *request
	err chan error
}

// HTLCManagerConfig defines the configuration for the htlcManager. ALL elements
// within the configuration MUST be non-nil for the htlcManager to carry out its
// duties.
type HTLCManagerConfig struct {
	// DecodeOnion function responsible for decoding HTLC onion blob, and
	// create hop iterator which gives us next route hop. This function
	// is included in config because of test purpose where instead of sphinx
	// encoded route we use simple array of hops.
	DecodeOnion func(data [lnwire.OnionPacketSize]byte, meta []byte) (
		routing.HopIterator, error)

	// Forward is a function which is used to Forward the incoming HTLC
	// requests to other peer which should handle it.
	Forward func(*request) error

	// Peer is a lightning network node with which we have create managed
	// channel.
	Peer Peer

	// Registry is a sub-system which responsible for managing the
	// invoices set in thread-safe manner .
	Registry InvoiceDatabase

	// SettledContracts is used to notify the breachArbiter that a channel
	// has peacefully been closed. Once a channel has been closed the
	// arbiter no longer needs to watch for breach closes.
	SettledContracts chan *wire.OutPoint

	// DebugHTLC should be turned on if you want all HTLCs sent to a node
	// with the debug HTLC R-Hash are immediately settled in the next
	// available state transition.
	DebugHTLC bool
}

// htlcManager is the service which drives a channel's commitment update
// state-machine in Err to messages received from remote peer or
// forwarded to as from HTLC switch. In the event that an HTLC needs to be
// forwarded, then Forward handler is used which sends HTLC to the switch for
// forwarding. Additionally, the htlcManager encapsulate logic of commitment
// protocol message ordering and updates.
type htlcManager struct {
	started  int32
	shutdown int32
	wg       sync.WaitGroup
	quit     chan bool

	// cfg is a structure which carries all dependable fields/handler
	// which may affect behaviour of thi service.
	cfg *HTLCManagerConfig

	// notSettleHTLCs is a map of outgoing HTLC's we've committed to in
	// our chain which have not yet been settled by the peer.
	notSettleHTLCs map[uint64]*request

	// cancelReasons stores the reason why a particular HTLC was cancelled.
	// The index of the HTLC within the log is mapped to the cancellation
	// reason. This value is used to thread the proper error through to the
	// htlcSwitch, or subsystem that initiated the HTLC.
	cancelReasons map[uint64]lnwire.OpaqueReason

	// blobs tracks the remote log index of the incoming HTLC's,
	// mapped to the htlc blob which encapsulate next hop.
	blobs map[uint64][lnwire.OnionPacketSize]byte

	// channel is a lightning network channel to which we apply htlc requests.
	channel *lnwallet.LightningChannel

	// commands is a channel which used for handling the inner system
	// requests.
	commands chan interface{}

	// delayedUpdateTicker is a update ticker which is sent upon if
	// we go an interval without receiving/sending a commitment update. It's
	// role is to ensure both chains converge to identical state in a timely
	// manner.
	delayedUpdateTicker *time.Ticker

	// delayedUpdate is a channel of update ticker which triggers the
	// update commit update.
	delayedUpdate <-chan time.Time
}

// A compile time check to ensure htlcManager implements the
// HTLCManager interface.
var _ HTLCManager = (*htlcManager)(nil)

// NewHTLCManager create new instance of htlc manager.
func NewHTLCManager(cfg *HTLCManagerConfig,
	channel *lnwallet.LightningChannel) HTLCManager {

	return &htlcManager{
		cfg:                 cfg,
		channel:             channel,
		notSettleHTLCs:      make(map[uint64]*request),
		blobs:               make(map[uint64][lnwire.OnionPacketSize]byte),
		commands:            make(chan interface{}),
		cancelReasons:       make(map[uint64]lnwire.OpaqueReason),
		delayedUpdateTicker: time.NewTicker(updateDelay),
		quit:                make(chan bool, 1),
	}
}

// HandleMessage handles the htlc requests which sent to us form remote peer.
// NOTE: Part of the HTLCManager interface.
func (mgr *htlcManager) HandleMessage(message lnwire.Message) error {
	command := &handleMessageCommand{
		message: message,
		err:     make(chan error),
	}

	select {
	case mgr.commands <- command:
		err := <-command.err
		if err != nil {
			log.Errorf("error while message handling in htlc "+
				"manager(%v): %v", mgr.ID(), err)
		}
		return err

	case <-mgr.quit:
		return nil
	}
}

// handleMessage handles the remote peer messages.
func (mgr *htlcManager) handleMessage(message lnwire.Message) error {
	switch msg := message.(type) {

	case *lnwire.UpdateFailHTLC:
		if err := mgr.channel.ReceiveFailHTLC(msg.ID); err != nil {
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("unable to recv HTLC cancel: %v", err)
		}

		// As far as we send cancellation message only after HTLC will
		// be included we should save the reason of HTLC cancellation
		// and then use it later to notify user or propagate cancel HTLC
		// message to another peer over htlc switch.
		mgr.cancelReasons[msg.ID] = msg.Reason
		mgr.delayedUpdateCommitTx()

	case *lnwire.UpdateAddHTLC:
		// We just received an add request from an remote peer, so we
		// add it to our state machine.
		index, err := mgr.channel.ReceiveHTLC(msg)
		if err != nil {
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("receiving HTLC rejected: %v", err)
		}

		// TODO(roasbeef): perform sanity checks on per-hop payload
		//  * time-lock is sane, fee, chain, etc

		// Store the onion blob which encapsulate the HTLC route and
		// use in on stage of HTLC inclusion to propagate the HTLC
		// farther.
		mgr.blobs[index] = msg.OnionBlob
		mgr.delayedUpdateCommitTx()

	case *lnwire.UpdateFufillHTLC:
		// TODO(roasbeef): this assumes no "multi-sig"
		pre := msg.PaymentPreimage
		if err := mgr.channel.ReceiveHTLCSettle(pre, msg.ID); err != nil {
			// TODO(roasbeef): broadcast on-chain
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("settle for outgoing HTLC rejected: %v", err)
		}
		mgr.delayedUpdateCommitTx()

	// TODO(roasbeef): add pre-image to DB in order to swipe
	// repeated r-values
	case *lnwire.CommitSig:
		// We just received a new update to our local commitment chain,
		// validate this new commitment, closing the link if invalid.
		sig := msg.CommitSig.Serialize()
		if err := mgr.channel.ReceiveNewCommitment(sig); err != nil {
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("unable to accept new commitment: %v", err)
		}

		if err := mgr.updateCommitTx(); err != nil {
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("can't update commit tx: "+
				"%v", err)
		}

		// Finally, since we just accepted a new state, send the remote
		// peer a revocation for our prior cm.
		revocation, err := mgr.channel.RevokeCurrentCommitment()
		if err != nil {
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("unable to revoke current commitment: "+
				"%v", err)
		}
		mgr.cfg.Peer.SendMessage(revocation)

	case *lnwire.RevokeAndAck:
		// We've received a revocation from the remote chain, if valid,
		// this moves the remote chain Forward, and expands our
		// revocation window.
		htlcs, err := mgr.channel.ReceiveRevocation(msg)
		if err != nil {
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("unable to accept revocation: %v", err)
		}

		// After we treat HTLCs as included in both
		// remote/local commitment transactions they might be
		// safely propagated over HTLC switch or settled if our node was
		// last node in HTLC path.
		requestsToForward, err := mgr.processHTLCsIncludedInBothChains(htlcs)
		if err != nil {
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("unbale procees included htlcs: %v", err)
		}

		go func() {
			for _, request := range requestsToForward {
				err := mgr.cfg.Forward(request)
				if err != nil {
					log.Errorf("error while Forward htlc "+
						"over htlc switch: %v", err)
				}
			}
		}()

	default:
		return errors.New("unknown message type")
	}

	return nil

}

// HandleMessage handles the HTLC requests which sent to us from remote peer.
// NOTE: Part of the HTLCManager interface.
func (mgr *htlcManager) HandleRequest(request *request) error {
	command := &requestForward{
		req: request,
		err: make(chan error),
	}

	select {
	case mgr.commands <- command:
		err := <-command.err
		if err != nil {
			log.Errorf("error while request handling in htlc "+
				"manager(%v): %v", mgr.ID(), err)
		}
		return err

	case <-mgr.quit:
		return nil
	}
}

// handleRequest handles HTLC switch requests which was forwarded to us from
// another channel, or sent to us from user who wants to send the payment.
func (mgr *htlcManager) handleRequest(request *request) error {
	switch htlc := request.htlc.(type) {
	case *lnwire.UpdateAddHTLC:
		// A new payment has been initiated, so we add the new HTLC
		// to our local log and the send it remote peer.
		htlc.ChannelPoint = *mgr.ID()
		index, err := mgr.channel.AddHTLC(htlc)
		if err != nil {
			// TODO: possibly perform fallback/retry logic
			// depending on type of error
			return errors.Errorf("adding HTLC rejected: %v", err)
		}

		mgr.notSettleHTLCs[index] = request
		mgr.cfg.Peer.SendMessage(htlc)

	case *lnwire.UpdateFufillHTLC:
		// HTLC switch notified us that HTLC which we forwarded was
		// settled, so we need to propagate this htlc to remote
		// peer.

		preimage := htlc.PaymentPreimage
		index, err := mgr.channel.SettleHTLC(preimage)
		if err != nil {
			// TODO(roasbeef): broadcast on-chain
			mgr.cfg.Peer.Disconnect()
			return errors.Errorf("settle for incoming HTLC rejected: %v", err)
		}

		htlc.ChannelPoint = *mgr.ID()
		htlc.ID = index

		mgr.cfg.Peer.SendMessage(htlc)

	case *lnwire.UpdateFailHTLC:
		// HTLC switch notified us that HTLC which we forwarded was
		// canceled, so we need to propagate this htlc to remote
		// peer.
		mgr.sendHTLCError(request.payHash, htlc.Reason)
	}

	return nil
}

// Start starts all helper goroutines required for the operation of the HTLC
// manager.
func (mgr *htlcManager) Start() error {
	if !atomic.CompareAndSwapInt32(&mgr.started, 0, 1) {
		log.Warn("htlc manager(%v) already started", mgr.ID())
		return nil
	}

	log.Info("htlc manager(%v) starting", mgr.ID())

	// If daemon was shut down during waiting for update, than
	// commitment update message wasn't sent. For that reason we need to
	// ensure that we include in commit transactions all htlc updates and
	// send it to the remote side update.
	mgr.delayedUpdateCommitTx()

	mgr.wg.Add(1)
	go mgr.startHandle()

	// A new session for this active channel has just started, therefore we
	// need to send our initial revocation window to the remote peer.
	for i := 0; i < lnwallet.InitialRevocationWindow; i++ {
		revocation, err := mgr.channel.ExtendRevocationWindow()
		if err != nil {
			log.Errorf("unable to expand revocation window: %v", err)
			continue
		}
		mgr.cfg.Peer.SendMessage(revocation)
	}

	return nil
}

// Stop gracefully stops all active helper goroutines, then waits until they've
// exited.
func (mgr *htlcManager) Stop() {
	if !atomic.CompareAndSwapInt32(&mgr.shutdown, 0, 1) {
		log.Warn("htlc manager(%v) already stopped", mgr.ID())
		return
	}

	log.Info("htlc manager(%v) stopping", mgr.ID())

	close(mgr.quit)
}

// Wait waits for service to stop.
// NOTE: This function is separated from Stop function because of deadlock
// possibility - when in handler itself we trigger Stop function of this
// service it leads to deadlock. (for example in WipeChannel function)
func (mgr *htlcManager) Wait() {
	mgr.wg.Wait()
}

// startHandle handles the channel closing notifications.
// NOTE: Should be started as goroutine.
func (mgr *htlcManager) startHandle() {
	defer mgr.wg.Done()
	// TODO(roasbeef): check to see if able to settle any currently pending
	// HTLC's
	//   * also need signals when new invoices are added by the invoiceRegistry

	for {
		select {
		case <-mgr.channel.UnilateralCloseSignal:
			// TODO(roasbeef): need to send HTLC outputs to nursery
			log.Warnf("Remote peer has closed channelPoint(%v) "+
				"on-chain",
				mgr.ID())
			if err := mgr.cfg.Peer.WipeChannel(mgr.channel); err !=
				nil {
				log.Errorf("unable to wipe channel %v", err)
			}

			mgr.cfg.SettledContracts <- mgr.channel.ChannelPoint()
			return

		case <-mgr.channel.ForceCloseSignal:
			log.Warnf("channelPoint(%v) has been force "+
				"closed, disconnecting from peerID(%x)",
				mgr.ID(), mgr.Peer().ID())
			return

		case command := <-mgr.commands:
			switch r := command.(type) {
			case *handleMessageCommand:
				r.err <- mgr.handleMessage(r.message)
			case *requestForward:
				r.err <- mgr.handleRequest(r.req)
			}

		case <-mgr.delayedUpdate:
			if err := mgr.updateCommitTx(); err != nil {
				log.Errorf("can't immediately update commit "+
					"tx: %v", err)
				mgr.cfg.Peer.Disconnect()
				return
			}

		case <-mgr.quit:
			return
		}
	}
}

// processHTLCsIncludedInBothChains this function is used to proceed the HTLCs
// which was designated as eligible for forwarding. But not all HTLC will be
// forwarder, if HTLC reached its final destination that we should settle it.
func (mgr *htlcManager) processHTLCsIncludedInBothChains(
	paymentDescriptors []*lnwallet.PaymentDescriptor) ([]*request,
	error) {

	var requestsToForward []*request
	for _, pd := range paymentDescriptors {
		// TODO(roasbeef): rework log entries to a shared
		// interface.
		switch pd.EntryType {

		case lnwallet.Settle:
			// Trying to find the pending HTLC to which this
			// settle HTLC belongs.
			request, ok := mgr.notSettleHTLCs[pd.ParentIndex]
			if !ok {
				continue
			}
			delete(mgr.notSettleHTLCs, pd.ParentIndex)

			switch request.rType {
			case userAddRequest:
				// Notify user that his payment was
				// successfully proceed.
				request.response.Err <- nil
				request.response.Preimage <- pd.RPreimage

			case forwardAddRequest:
				// If this request came from switch that we
				// should Forward settle message back to peer.
				requestsToForward = append(requestsToForward,
					newForwardSettleRequest(
						mgr.ID(),
						&lnwire.UpdateFufillHTLC{
							PaymentPreimage: pd.RPreimage,
						}))
			}

		case lnwallet.Fail:
			request, ok := mgr.notSettleHTLCs[pd.ParentIndex]
			if !ok {
				continue
			}
			delete(mgr.notSettleHTLCs, pd.ParentIndex)
			opaqueReason := mgr.cancelReasons[pd.ParentIndex]

			switch request.rType {
			case userAddRequest:
				// TODO(andrew.shvv) Finish when the usage of
				// opaque reason become more clear.
				code := binary.BigEndian.Uint16(opaqueReason)
				failCode := lnwire.FailCode(code)

				// Notify user that his payment was canceled.
				request.response.Err <- errors.New(failCode.String())

			case forwardAddRequest:
				// If this request came from switch that we
				// should Forward cancel message back to peer.
				requestsToForward = append(requestsToForward,
					newFailRequest(
						mgr.ID(),
						&lnwire.UpdateFailHTLC{
							Reason:       opaqueReason,
							ChannelPoint: *mgr.ID(),
							ID:           pd.Index,
						},
						pd.RHash))
			}

		case lnwallet.Add:
			blob := mgr.blobs[pd.Index]
			delete(mgr.blobs, pd.Index)

			// Before adding the new HTLC to the state machine,
			// parse the onion object in order to obtain the routing
			// information with DecodeOnion function which process
			// the Sphinx packet.
			// We include the payment hash of the HTLC as it's
			// authenticated within the Sphinx packet itself as
			// associated data in order to thwart attempts a replay
			// attacks. In the case of a replay, an attacker is
			// *forced* to use the same payment hash twice, thereby
			// losing their money entirely.
			hopIterator, err := mgr.cfg.DecodeOnion(blob, pd.RHash[:])
			if err != nil {
				// If we're unable to parse the Sphinx packet,
				// then we'll cancel the HTLC.
				log.Errorf("unable to get the next hop: %v", err)
				mgr.sendHTLCError(pd.RHash, []byte{byte(lnwire.SphinxParseError)})
				continue
			}

			if dest := hopIterator.Next(); dest != nil {
				// There are additional hops left within this
				// route.
				nextBlob, err := hopIterator.ToBytes()
				if err != nil {
					log.Errorf("unable to encode the hop "+
						"iterator: %v", err)
					continue
				}

				var blob [lnwire.OnionPacketSize]byte
				copy(blob[:], nextBlob)

				requestsToForward = append(requestsToForward,
					newForwardAddRequest(
						dest, mgr.ID(),
						&lnwire.UpdateAddHTLC{
							Amount:      pd.Amount,
							PaymentHash: pd.RHash,
							OnionBlob:   blob,
						}))
			} else {
				// We're the designated payment destination.
				// Therefore we attempt to see if we have an
				// invoice locally which'll allow us to settle
				// this HTLC.
				invoiceHash := chainhash.Hash(pd.RHash)
				invoice, err := mgr.cfg.Registry.LookupInvoice(invoiceHash)
				if err != nil {
					log.Errorf("unable to query to locate:"+
						" %v", err)
					reason := []byte{byte(lnwire.UnknownPaymentHash)}
					mgr.sendHTLCError(pd.RHash, reason)
					continue
				}

				// If we're not currently in debug mode, and the
				// extended HTLC doesn't meet the value requested,
				// then we'll fail the HTLC. Otherwise, we settle
				// this HTLC within our local state update log,
				// then send the update entry to the remote party.
				if !mgr.cfg.DebugHTLC && pd.Amount < invoice.Terms.Value {
					log.Errorf("rejecting HTLC due to incorrect "+
						"amount: expected %v, received %v",
						invoice.Terms.Value, pd.Amount)
					reason := []byte{byte(lnwire.IncorrectValue)}
					mgr.sendHTLCError(pd.RHash, reason)
					continue
				}

				preimage := invoice.Terms.PaymentPreimage
				logIndex, err := mgr.channel.SettleHTLC(preimage)
				if err != nil {
					return nil, errors.Errorf("unable to "+
						"settle htlc: %v", err)
				}

				// Notify the invoiceRegistry of the invoices we
				// just settled with this latest commitment
				// update.
				err = mgr.cfg.Registry.SettleInvoice(invoiceHash)
				if err != nil {
					return nil, errors.Errorf("unable to "+
						"settle invoice: %v", err)
				}

				// HTLC was successfully settled locally send
				// notification about it remote peer.
				mgr.cfg.Peer.SendMessage(&lnwire.UpdateFufillHTLC{
					ChannelPoint:    *mgr.ID(),
					ID:              logIndex,
					PaymentPreimage: preimage,
				})
			}
		}
	}

	return requestsToForward, nil
}

// sendHTLCError functions cancels HTLC and send cancel message back to the
// peer from which HTLC was received.
func (mgr *htlcManager) sendHTLCError(rHash [32]byte,
	reason lnwire.OpaqueReason) {

	index, err := mgr.channel.FailHTLC(rHash)
	if err != nil {
		log.Errorf("can't cancel htlc: %v", err)
		return
	}

	mgr.cfg.Peer.SendMessage(&lnwire.UpdateFailHTLC{
		ChannelPoint: *mgr.ID(),
		ID:           index,
		Reason:       reason,
	})
}

// Bandwidth returns the amount of satohis which this HTLC manager can
// handle at this time.
// NOTE: Part of the HTLCManager interface.
func (mgr *htlcManager) Bandwidth() btcutil.Amount {
	snapshot := mgr.channel.StateSnapshot()
	return snapshot.LocalBalance
}

// SatSent returns the amount of satoshis which was successfully sent
// and settled.
// NOTE: Part of the HTLCManager interface.
func (mgr *htlcManager) SatSent() btcutil.Amount {
	snapshot := mgr.channel.StateSnapshot()
	return btcutil.Amount(snapshot.TotalSatoshisSent)
}

// SatRecv returns the amount of satoshis which was successfully
// received and settled.
// NOTE: Part of the HTLCManager interface.
func (mgr *htlcManager) SatRecv() btcutil.Amount {
	snapshot := mgr.channel.StateSnapshot()
	return btcutil.Amount(snapshot.TotalSatoshisReceived)
}

// NumUpdates returns the number of updates which was applied to channel
// which corresponds to this HTLC manager.
// NOTE: Part of the HTLCManager interface.
func (mgr *htlcManager) NumUpdates() uint64 {
	snapshot := mgr.channel.StateSnapshot()
	return snapshot.NumUpdates
}

// ID returns the id of the htlc manager which is equivalent to channel
// point the managed channel.
// NOTE: Part of the HTLCManager interface.
func (mgr *htlcManager) ID() *wire.OutPoint {
	return mgr.channel.ChannelPoint()
}

// Peer...
func (mgr *htlcManager) Peer() Peer {
	return mgr.cfg.Peer
}

// delayedUpdateCommitTx used to delay update of commitment transaction when we
// receive HTLC update. Such behaviour reduces the number of commitment update
// message between nodes in case of intensive flow of HTLC updates as far
// as update will be triggered not each time, but instead if number of
// HTLCs was received during update period than only one update will be
// triggered. Example:
//
// htlc arrived
// and delayed
// channel state
// update was           update channel state.
// initiated                       |
// with period T.                  |
//    |                            |
//    |                            |
// o--x----x-x-x-----x-------------x------> t
//    |    | | |     |             |
//    |    \_\_\____/              |
//    |         |                  |
//    | another htlcs are arrived  |
//    | but update already         |
//    | initiated.                 |
//    |                            |
//    | <------------------------> |
//                  T
//
func (mgr *htlcManager) delayedUpdateCommitTx() {
	// If update was already initiated than wait for it to be triggered.
	if mgr.delayedUpdate == nil {
		mgr.delayedUpdateTicker = time.NewTicker(updateDelay)
		mgr.delayedUpdate = mgr.delayedUpdateTicker.C
	}
}

// updateCommitTx signs, then sends an commit tx update to the remote peer
// adding a new commitment to their commitment chain which includes all the
// latest updates we've received+processed up to this point.
func (mgr *htlcManager) updateCommitTx() error {
	if mgr.channel.NeedUpdate() || !mgr.channel.FullySynced() {
		sigTheirs, err := mgr.channel.SignNextCommitment()
		if err == lnwallet.ErrNoWindow {
			log.Trace(err)
			return nil
		} else if err != nil {
			return errors.Errorf("unable to update commitment: %v", err)
		}

		parsedSig, err := btcec.ParseSignature(sigTheirs, btcec.S256())
		if err != nil {
			return errors.Errorf("unable to update commitment: %v", err)
		}

		commitSig := &lnwire.CommitSig{
			ChannelPoint: *mgr.ID(),
			CommitSig:    parsedSig,
		}

		if err := mgr.cfg.Peer.SendMessage(commitSig); err != nil {
			return errors.Errorf("unable to update commitment: %v", err)
		}
	}

	// By setting the channel to nil, we make available for
	// another delayed update to be triggered.
	mgr.delayedUpdate = nil

	// Prevent ticker from leaking.
	mgr.delayedUpdateTicker.Stop()

	return nil
}
