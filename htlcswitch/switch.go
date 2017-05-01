package htlcswitch

import (
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"

	"bytes"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

var (
	// ErrChannelLinkNotFound is used when channel link hasn't been found.
	ErrChannelLinkNotFound = errors.New("channel link not found")

	// zeroPreimage is the empty preimage which is returned when we have
	// some errors.
	zeroPreimage [sha256.Size]byte
)

// pendingPayment represents the payment which made by user and waits for
// updates to be received whether the payment has been rejected or proceed
// successfully.
type pendingPayment struct {
	// TODO(andrew.shvv) use payment hash instead after implementing sphinx
	// payment.
	index uint64

	err      chan error
	preimage chan [sha256.Size]byte
}

// forwardPacketCmd encapsulates switch packet and adds error channel to
// receive error from request handler.
type forwardPacketCmd struct {
	pkt *htlcPacket
	err chan error
}

// channelCloseType is a enum which signals the type of channel closure the
// peer should execute.
type channelCloseType uint8

const (
	// CloseRegular indicates a regular cooperative channel closure
	// should be attempted.
	CloseRegular channelCloseType = iota

	// CloseForce indicates that the channel should be forcefully closed.
	// This entails the broadcast of the commitment transaction directly on
	// chain unilaterally.
	CloseForce

	// CloseBreach indicates that a channel breach has been dtected, and
	// the link should immediately be marked as unavailable.
	CloseBreach
)

// ChanClose represents a request which close a particular channel specified by
// its id.
type ChanClose struct {
	// CloseType is a variable which signals the type of channel closure the
	// peer should execute.
	CloseType channelCloseType

	// ChanPoint represent the id of the channel which should be closed.
	ChanPoint *wire.OutPoint

	// Updates is used by request creator to receive the notifications about
	// execution of the close channel request.
	Updates chan *lnrpc.CloseStatusUpdate

	// Err is used by request creator to receive request execution error.
	Err chan error
}

// Config defines the configuration for the service. ALL elements within the
// configuration MUST be non-nil for the service to carry out its duties.
type Config struct {
	// LocalChannelClose kicks-off the workflow to execute a cooperative
	// or forced unilateral closure of the channel initiated by a local
	// subsystem.
	LocalChannelClose func(pubKey []byte, request *ChanClose)
}

// Switch is a central messaging bus for all incoming/outgoing htlc's.
// The goal of the switch is forward the incoming/outgoing htlc messages from
// one channel to another, and also propagate the settle/fail htlc messages
// back to original requester by using payment circuits. Also switch is
// responsible for notifying the user about result of payment request.
type Switch struct {
	started  int32
	shutdown int32
	wg       sync.WaitGroup
	quit     chan struct{}
	mutex    sync.RWMutex

	// cfg is a copy of the configuration struct that the htlc switch
	// service was initialized with.
	cfg *Config

	// pendingPayments is correspondence of user payments and its hashes,
	// which is used to save the payments which made by user and notify
	// them about result later.
	pendingPayments map[uint64]*pendingPayment
	pendingMutex    sync.RWMutex

	// circuits is storage for payment circuits which are used to
	// forward the settle/fail htlc updates back to the add htlc initiator.
	circuits *circuitMap

	// links is a map of channel id and channel link which manages
	// this channel.
	links map[lnwire.ChannelID]ChannelLink

	// forwardCommands is used for propogating the htlc packet forward
	// requests.
	forwardCommands chan *forwardPacketCmd

	// chanCloseRequests is used to transfer the channel close request to
	// the channel close handler.
	chanCloseRequests chan *ChanClose
}

// New creates the new instance of htlc switch.
func New(cfg Config) *Switch {
	return &Switch{
		cfg:               &cfg,
		circuits:          newCircuitMap(),
		links:             make(map[lnwire.ChannelID]ChannelLink),
		pendingPayments:   make(map[uint64]*pendingPayment),
		forwardCommands:   make(chan *forwardPacketCmd),
		chanCloseRequests: make(chan *ChanClose),
		quit:              make(chan struct{}),
	}
}

// SendUpdate is used by other subsystems which aren't belong to htlc swicth
// package in order to send the htlc update.
func (s *Switch) SendUpdate(nextNode []byte, update lnwire.Message) (
	chan [sha256.Size]byte, chan error) {

	htlc := update.(*lnwire.UpdateAddHTLC)

	// Create payment and add to the map of payment in order later to be
	// able to retrieve it and return response to the user.
	payment := &pendingPayment{
		err:      make(chan error, 1),
		preimage: make(chan [sha256.Size]byte, 1),
		index:    htlc.ID,
	}

	// Check that we do not have the payment with the same id in order to
	// prevent map override.
	s.pendingMutex.Lock()
	_, ok := s.pendingPayments[htlc.ID]
	if ok {
		s.pendingMutex.Unlock()
		payment.preimage <- zeroPreimage
		payment.err <- errors.Errorf("pending payment with id (%v) "+
			"already exist", htlc.ID)
		return payment.preimage, payment.err
	}
	s.pendingPayments[htlc.ID] = payment
	s.pendingMutex.Unlock()

	// Generate and send new update packet, if error will be received
	// on this stage it means that packet haven't left boundaries of our
	// system and something wrong happened.
	hop := newHopID(nextNode)
	packet := newInitPacket(hop, htlc)
	if err := s.Forward(packet); err != nil {
		payment.preimage <- zeroPreimage
		payment.err <- err
		return payment.preimage, payment.err
	}

	// Returns channels so that other subsystem might wait/skip the
	// waiting of handling of payment.
	return payment.preimage, payment.err
}

// Forward is used in order to find next channel link and apply htlc
// update. Also this function is used by channel links itself in order to
// forward the update after it has been included in the channel.
func (s *Switch) Forward(packet *htlcPacket) error {
	command := &forwardPacketCmd{
		pkt: packet,
		err: make(chan error),
	}

	select {
	case s.forwardCommands <- command:
		return <-command.err
	case <-s.quit:
		return errors.New("Htlc Switch was stopped")
	}
}

// handleForward handles incoming forward commands.
func (s *Switch) handleForward(command *forwardPacketCmd) {
	var index uint64

	switch m := command.pkt.htlc.(type) {
	case *lnwire.UpdateAddHTLC:
		index = m.ID
	case *lnwire.UpdateFufillHTLC:
		index = m.ID
	case *lnwire.UpdateFailHTLC:
		index = m.ID
	default:
		command.err <- errors.New("wrong type of update")
		return
	}

	s.pendingMutex.RLock()
	payment, ok := s.pendingPayments[index]
	s.pendingMutex.RUnlock()

	if ok {
		command.err <- s.handleStartAndEndPacket(payment, command.pkt)
	} else {
		command.err <- s.handleChannelLinkPacket(command.pkt)
	}
}

// handleStartAndEndPacket is used at the start/end of the htlc update life
// cycle. At the start (1) it is used to send the htlc to the channel link
// without creation of circuit. At the end (2) it is used to notify the user
// about the result of his payment is it was successful or not.
//
//   Alice         Bob          Carol
//     o --add----> o ---add----> o
//    (1)
//
//    (2)
//     o <-settle-- o <--settle-- o
//   Alice         Bob         Carol
//
func (s *Switch) handleStartAndEndPacket(payment *pendingPayment, packet *htlcPacket) error {
	switch htlc := packet.htlc.(type) {

	// User have created the htlc update therefore we should find the
	// appropriate channel link and send the payment over this link.
	case *lnwire.UpdateAddHTLC:
		// Try to find links by node destination.
		links, err := s.getLinks(packet.dest)
		if err != nil {
			log.Errorf("unable to find links by "+
				"destination %v", err)
			return errors.New(lnwire.UnknownDestination)
		}

		// Try to find destination channel link with appropriate
		// bandwidth.
		var destination ChannelLink
		for _, link := range links {
			if link.Bandwidth() >= htlc.Amount {
				destination = link
				break
			}
		}

		// If the channel link we're attempting to forward the update
		// over has insufficient capacity, then we'll cancel the HTLC
		// as the payment cannot succeed.
		if destination == nil {
			log.Errorf("unable to find appropriate channel link "+
				"insufficient capacity, need %v", htlc.Amount)
			return errors.New(lnwire.InsufficientCapacity)
		}

		// Send the packet to the destination channel link which
		// manages then channel.
		go destination.HandleSwitchPacket(packet)
		return nil

	// We've just received a settle update which means we can finalize
	// the user payment and return successful response.
	case *lnwire.UpdateFufillHTLC:
		// Notify the user that his payment was
		// successfully proceed.
		payment.err <- nil
		payment.preimage <- htlc.PaymentPreimage

		s.pendingMutex.Lock()
		delete(s.pendingPayments, payment.index)
		s.pendingMutex.Unlock()

	// We've just received a fail update which means we can finalize
	// the user payment and return fail response.
	case *lnwire.UpdateFailHTLC:
		// Retrieving the fail code from byte representation of error.
		code, err := htlc.Reason.ToFailCode()
		if err != nil {
			return errors.Errorf("can't decode fail code id(%v)"+
				":%v", htlc.ID, err)
		}

		// Notify user that his payment was discarded.
		var zeroPreimage [32]byte
		payment.err <- errors.New(code)
		payment.preimage <- zeroPreimage

		s.pendingMutex.Lock()
		delete(s.pendingPayments, payment.index)
		s.pendingMutex.Unlock()

	default:
		return errors.New("wrong update type")
	}

	return nil
}

// handleChannelLinkPacket is used in cases when we need forward the htlc
// update from one channel link to another and be able to propagate the
// settle/fail updates back. This behaviour is achieved by creation of payment
// circuits.
func (s *Switch) handleChannelLinkPacket(packet *htlcPacket) error {
	switch htlc := packet.htlc.(type) {

	// Channel link forwarded us a new htlc, therefore we initiate the
	// payment circuit within our internal state so we can properly forward
	// the ultimate settle message back latter.
	case *lnwire.UpdateAddHTLC:
		source, err := s.GetLink(packet.src)
		if err != nil {
			err := errors.Errorf("unable to find channel link "+
				"by channel point (%v): %v", packet.src, err)
			log.Error(err)
			return err
		}

		// Try to find links by node destination.
		links, err := s.getLinks(packet.dest)
		if err != nil {
			// If packet was forwarded from another
			// channel link than we should notify this
			// link that some error occurred.
			reason := []byte{byte(lnwire.UnknownDestination)}
			go source.HandleSwitchPacket(newFailPacket(
				packet.src,
				&lnwire.UpdateFailHTLC{
					Reason: reason,
				},
				htlc.PaymentHash,
			))
			err := errors.Errorf("unable to find links with "+
				"destination %v", err)
			log.Error(err)
			return err
		}

		// Try to find destination channel link with appropriate
		// bandwidth.
		var destination ChannelLink
		for _, link := range links {
			if link.Bandwidth() >= htlc.Amount {
				destination = link
				break
			}
		}

		// If the channel link we're attempting to forward the update
		// over has insufficient capacity, then we'll cancel the htlc
		// as the payment cannot succeed.
		if destination == nil {
			// If packet was forwarded from another
			// channel link than we should notify this
			// link that some error occurred.
			reason := []byte{byte(lnwire.InsufficientCapacity)}
			go source.HandleSwitchPacket(newFailPacket(
				packet.src,
				&lnwire.UpdateFailHTLC{
					Reason: reason,
				},
				htlc.PaymentHash,
			))

			err := errors.Errorf("unable to find appropriate "+
				"channel link insufficient capacity, need "+
				"%v", htlc.Amount)
			log.Error(err)
			return err
		}

		// If packet was forwarded from another channel link than we
		// should create circuit (remember the path) in order to
		// forward settle/fail packet back.
		if err := s.circuits.add(newPaymentCircuit(
			source.ChanID(),
			destination.ChanID(),
			htlc.PaymentHash,
		)); err != nil {
			reason := []byte{byte(lnwire.UnknownError)}
			go source.HandleSwitchPacket(newFailPacket(
				packet.src,
				&lnwire.UpdateFailHTLC{
					Reason: reason,
				},
				htlc.PaymentHash,
			))
			err := errors.Errorf("unable to add circuit: "+
				"%v", err)
			log.Error(err)
			return err
		}

		// Send the packet to the destination channel link which
		// manages the channel.
		go destination.HandleSwitchPacket(packet)
		return nil

	// We've just received a settle packet which means we can finalize the
	// payment circuit by forwarding the settle msg to the channel from
	// which htlc add packet was initially received.
	case *lnwire.UpdateFufillHTLC, *lnwire.UpdateFailHTLC:
		// Exit if we can't find and remove the active circuit to
		// continue propagating the fail over.
		circuit, err := s.circuits.remove(packet.payHash, packet.src)
		if err != nil {
			err := errors.Errorf("unable to remove "+
				"circuit for payment hash: %v", packet.payHash)
			log.Error(err)
			return err
		}

		// Propagating settle htlc back to src of add htlc packet.
		source, err := s.GetLink(circuit.Src)
		if err != nil {
			err := errors.Errorf("unable to get src "+
				"channel link to Forward settle htlc: %v", err)
			log.Error(err)
			return err
		}

		log.Debugf("Closing completed onion "+
			"circuit for %x: %v<->%v", packet.payHash[:],
			circuit.Src, circuit.Dest)

		go source.HandleSwitchPacket(packet)
		return nil

	default:
		return errors.New("wrong update type")
	}
}

// CloseLink creates and sends the the close channel command.
func (s *Switch) CloseLink(chanPoint *wire.OutPoint,
	closeType channelCloseType) (chan *lnrpc.CloseStatusUpdate, chan error) {

	updateChan := make(chan *lnrpc.CloseStatusUpdate, 1)
	errChan := make(chan error, 1)

	command := &ChanClose{
		CloseType: closeType,
		ChanPoint: chanPoint,
		Updates:   updateChan,
		Err:       errChan,
	}

	select {
	case s.chanCloseRequests <- command:
		return updateChan, errChan

	case <-s.quit:
		errChan <- errors.New("unable close channel link, htlc " +
			"swicth already stopped")
		close(updateChan)
		return updateChan, errChan
	}
}

// handleCloseLink sends a message to the peer responsible for the target
// channel point, instructing it to initiate a cooperative channel closure.
func (s *Switch) handleChanelClose(req *ChanClose) {
	chanID := lnwire.NewChanIDFromOutPoint(req.ChanPoint)

	var link ChannelLink
	s.mutex.RLock()
	for _, l := range s.links {
		if l.ChanID() == chanID {
			link = l
		}
	}
	s.mutex.RUnlock()

	if link == nil {
		req.Err <- errors.Errorf("channel with ChannelID(%v) not "+
			"found", chanID)
		return
	}

	log.Debugf("requesting local channel close, peer(%v) channel(%v)",
		link.Peer(), chanID)

	// TODO(roasbeef): if type was CloseBreach initiate force closure with
	// all other channels (if any) we have with the remote peer.
	s.cfg.LocalChannelClose(link.Peer().PubKey(), req)
	return
}

// startHandling start handling inner command requests and print the
// htlc switch statistics.
// NOTE: Should be run as goroutine.
func (s *Switch) startHandling() {
	defer s.wg.Done()

	// TODO(roasbeef): cleared vs settled distinction
	var prevNumUpdates uint64
	var prevSatSent btcutil.Amount
	var prevSatRecv btcutil.Amount

	for {
		select {
		case req := <-s.chanCloseRequests:
			s.handleChanelClose(req)

		case cmd := <-s.forwardCommands:
			s.handleForward(cmd)

		case <-time.Tick(10 * time.Second):
			var overallNumUpdates uint64
			var overallSatSent btcutil.Amount
			var overallSatRecv btcutil.Amount

			for _, link := range s.links {
				updates, sent, recv := link.Stats()
				overallNumUpdates += updates
				overallSatSent += sent
				overallSatRecv += recv
			}

			if overallNumUpdates == 0 {
				continue
			}

			diffNumUpdates := overallNumUpdates - prevNumUpdates
			diffSatSent := overallSatSent - prevSatSent
			diffSatRecv := overallSatRecv - prevSatRecv

			log.Infof("sent %v satoshis received %v satoshi "+
				" in the last 10 seconds (%v tx/sec)",
				diffSatSent, diffSatRecv, float64(diffNumUpdates)/10)

			prevNumUpdates = overallNumUpdates
			prevSatSent = overallSatSent
			prevSatRecv = overallSatRecv

		case <-s.quit:
			return
		}
	}
}

// Start starts all helper goroutines required for the operation of the switch.
func (s *Switch) Start() error {
	if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		log.Warn("Htlc Switch already started")
		return nil
	}

	log.Infof("Htlc Switch starting")

	s.wg.Add(1)
	go s.startHandling()

	return nil
}

// Stop gracefully stops all active helper goroutines, then waits until they've
// exited.
func (s *Switch) Stop() error {
	if !atomic.CompareAndSwapInt32(&s.shutdown, 0, 1) {
		log.Warn("Htlc Switch already stopped")
		return nil
	}

	log.Infof("Htlc Switch shutting down")

	s.mutex.Lock()
	for _, link := range s.links {
		delete(s.links, link.ChanID())
		link.Stop()
		log.Infof("Remove channel link with ChannelID(%v)", link.ChanID())
	}
	s.mutex.Unlock()

	close(s.quit)
	s.wg.Wait()

	return nil
}

// AddLink is used to add and start the newly created channel link and start
// use it to handle the channel updates.
func (s *Switch) AddLink(link ChannelLink) error {
	if err := link.Start(); err != nil {
		return err
	}

	s.mutex.Lock()
	s.links[link.ChanID()] = link
	s.mutex.Unlock()

	log.Infof("Added channel link with ChannelID(%v), bandwidth=%v",
		link.ChanID(), link.Bandwidth())
	return nil
}

// GetLink returns the channel link by its channel point.
func (s *Switch) GetLink(chanID lnwire.ChannelID) (ChannelLink, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	link, ok := s.links[chanID]
	if !ok {
		return nil, ErrChannelLinkNotFound
	}

	return link, nil
}

// RemoveLink is used to remove and stop the channel link.
func (s *Switch) RemoveLink(chanID lnwire.ChannelID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	link, ok := s.links[chanID]
	if !ok {
		return ErrChannelLinkNotFound
	}

	delete(s.links, link.ChanID())
	link.Stop()
	log.Infof("Remove channel link with ChannelID(%v)", link.ChanID())

	return nil
}

// RemoveLinks removes all channel links by given node public key.
func (s *Switch) RemoveLinks(pubKey []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var links []ChannelLink
	for _, link := range s.links {
		if bytes.Equal(link.Peer().PubKey(), pubKey) {
			links = append(links, link)
		}
	}
	if links == nil {
		return errors.Errorf("unable to locate channel link by"+
			"public key %v", pubKey)
	}

	for _, link := range links {
		delete(s.links, link.ChanID())
		link.Stop()
		log.Infof("Remove channel link with ChannelID(%v)", link.ChanID())
	}

	return nil
}

// getLinks is helper function which returns the channel links by hop
// destination id.
func (s *Switch) getLinks(destination hopID) ([]ChannelLink,
	error) {

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var result []ChannelLink
	for _, link := range s.links {
		hopID := newHopID(link.Peer().PubKey())
		if hopID.IsEqual(destination) {
			result = append(result, link)
		}
	}
	if result == nil {
		return nil, errors.Errorf("unable to locate channel link by"+
			"destination hop id %v", destination)
	}
	return result, nil
}
