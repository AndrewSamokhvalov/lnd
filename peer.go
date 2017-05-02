package main

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/pkg/errors"

	"github.com/btcsuite/fastsha256"

	"bytes"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/connmgr"
	"github.com/roasbeef/btcd/txscript"
)

var (
	numNodes int32
)

const (
	// pingInterval is the interval at which ping messages are sent.
	pingInterval = 1 * time.Minute

	// outgoingQueueLen is the buffer size of the channel which houses
	// messages to be sent across the wire, requested by objects outside
	// this struct.
	outgoingQueueLen = 50
)

// outgoinMsg packages an lnwire.Message to be sent out on the wire, along with
// a buffered channel which will be sent upon once the write is complete. This
// buffered channel acts as a semaphore to be used for synchronization purposes.
type outgoinMsg struct {
	msg      lnwire.Message
	sentChan chan struct{} // MUST be buffered.
}

// newChannelMsg packages a lnwallet.LightningChannel with a channel that
// allows the receiver of the request to report when the funding transaction
// has been confirmed and the channel creation process completed.
type newChannelMsg struct {
	channel *lnwallet.LightningChannel
	done    chan struct{}
}

// chanSnapshotReq is a message sent by outside subsystems to a peer in order
// to gain a snapshot of the peer's currently active channels.
type chanSnapshotReq struct {
	resp chan []*channeldb.ChannelSnapshot
}

// peer is an active peer on the Lightning Network. This struct is responsible
// for managing any channel state related to this peer. To do so, it has
// several helper goroutines to handle events such as HTLC timeouts, new
// funding workflow, and detecting an uncooperative closure of any active
// channels.
// TODO(roasbeef): proper reconnection logic
type peer struct {
	// The following fields are only meant to be used *atomically*
	bytesReceived uint64
	bytesSent     uint64

	// pingTime is a rough estimate of the RTT (round-trip-time) between us
	// and the connected peer. This time is expressed in micro seconds.
	// TODO(roasbeef): also use a WMA or EMA?
	pingTime int64

	// pingLastSend is the Unix time expressed in nanoseconds when we sent
	// our last ping message.
	pingLastSend int64

	// MUST be used atomically.
	started    int32
	disconnect int32

	connReq *connmgr.ConnReq
	conn    net.Conn

	addr        *lnwire.NetAddress
	lightningID chainhash.Hash

	inbound bool
	id      int32

	// This mutex protects all the stats below it.
	sync.RWMutex
	timeConnected time.Time
	lastSend      time.Time
	lastRecv      time.Time

	// sendQueue is the channel which is used to queue outgoing to be
	// written onto the wire. Note that this channel is unbuffered.
	sendQueue chan outgoinMsg

	// outgoingQueue is a buffered channel which allows second/third party
	// objects to queue messages to be sent out on the wire.
	outgoingQueue chan outgoinMsg

	// sendQueueSync is used as a semaphore to synchronize writes between
	// the writeHandler and the queueHandler.
	sendQueueSync chan struct{}

	// activeChannels is a map which stores the state machines of all
	// active channels. Channels are indexed into the map by the txid of
	// the funding transaction which opened the channel.
	activeChanMtx    sync.RWMutex
	activeChannels   map[lnwire.ChannelID]*lnwallet.LightningChannel
	chanSnapshotReqs chan *chanSnapshotReq

	// newChannels is used by the fundingManager to send fully opened
	// channels to the source peer which handled the funding workflow.
	newChannels chan *newChannelMsg

	// localCloseChanReqs is a channel in which any local requests to close
	// a particular channel are sent over.
	localCloseChanReqs chan *htlcswitch.ChanClose

	// remoteCloseChanReqs is a channel in which any remote requests
	// (initiated by the remote peer) close a particular channel are sent
	// over.
	remoteCloseChanReqs chan *lnwire.CloseRequest

	server *server

	// localSharedFeatures is a product of comparison of our and their
	// local features vectors which consist of features which are present
	// on both sides.
	localSharedFeatures *lnwire.SharedFeatures

	// globalSharedFeatures is a product of comparison of our and their
	// global features vectors which consist of features which are present
	// on both sides.
	globalSharedFeatures *lnwire.SharedFeatures

	queueQuit chan struct{}
	quit      chan struct{}
	wg        sync.WaitGroup
}

// newPeer creates a new peer from an establish connection object, and a
// pointer to the main server.
func newPeer(conn net.Conn, connReq *connmgr.ConnReq, server *server,
	addr *lnwire.NetAddress, inbound bool) (*peer, error) {

	nodePub := addr.IdentityKey

	p := &peer{
		conn:        conn,
		lightningID: chainhash.Hash(sha256.Sum256(nodePub.SerializeCompressed())),
		addr:        addr,

		id:      atomic.AddInt32(&numNodes, 1),
		inbound: inbound,
		connReq: connReq,

		server: server,

		sendQueueSync: make(chan struct{}, 1),
		sendQueue:     make(chan outgoinMsg, 1),
		outgoingQueue: make(chan outgoinMsg, outgoingQueueLen),

		activeChannels:   make(map[lnwire.ChannelID]*lnwallet.LightningChannel),
		chanSnapshotReqs: make(chan *chanSnapshotReq),
		newChannels:      make(chan *newChannelMsg, 1),

		localCloseChanReqs:  make(chan *htlcswitch.ChanClose),
		remoteCloseChanReqs: make(chan *lnwire.CloseRequest),

		localSharedFeatures:  nil,
		globalSharedFeatures: nil,

		queueQuit: make(chan struct{}),
		quit:      make(chan struct{}),
	}

	return p, nil
}

// Start starts all helper goroutines the peer needs for normal operations.  In
// the case this peer has already been started, then this function is a loop.
func (p *peer) Start() error {
	if atomic.AddInt32(&p.started, 1) != 1 {
		return nil
	}

	peerLog.Tracef("peer %v starting", p)

	// Exchange local and global features, the init message should be very
	// first between two nodes.
	if err := p.sendInitMsg(); err != nil {
		return fmt.Errorf("unable to send init msg: %v", err)
	}

	// Before we launch any of the helper goroutines off the peer struct,
	// we'll first ensure proper adherence to the p2p protocol. The init
	// message MUST be sent before any other message.
	readErr := make(chan error, 1)
	msgChan := make(chan lnwire.Message, 1)
	go func() {
		msg, err := p.readNextMessage()
		if err != nil {
			readErr <- err
			msgChan <- nil
		}
		readErr <- nil
		msgChan <- msg
	}()

	select {
	// In order to avoid blocking indefinitely, we'll give the other peer
	// an upper timeout of 15 seconds to respond before we bail out early.
	case <-time.After(time.Second * 15):
		return fmt.Errorf("peer did not complete handshake within 5 " +
			"seconds")
	case err := <-readErr:
		if err != nil {
			return fmt.Errorf("unable to read init msg: %v", err)
		}
	}

	msg := <-msgChan
	if msg, ok := msg.(*lnwire.Init); ok {
		if err := p.handleInitMsg(msg); err != nil {
			return err
		}
	} else {
		return errors.New("very first message between nodes " +
			"must be init message")
	}

	p.wg.Add(5)
	go p.queueHandler()
	go p.writeHandler()
	go p.readHandler()
	go p.channelManager()
	go p.pingHandler()

	// Fetch and then load all the active channels we have with this remote
	// peer from the database.
	activeChans, err := p.server.chanDB.FetchOpenChannels(p.addr.IdentityKey)
	if err != nil {
		peerLog.Errorf("unable to fetch active chans "+
			"for peer %v: %v", p, err)
		return err
	}

	// Next, load all the active channels we have with this peer,
	// registering them with the switch and launching the necessary
	// goroutines required to operate them.
	peerLog.Debugf("Loaded %v active channels from database with "+
		"peerID(%v)", len(activeChans), p.id)
	if err := p.loadActiveChannels(activeChans); err != nil {
		return fmt.Errorf("unable to load channels: %v", err)
	}

	return nil
}

// loadActiveChannels creates indexes within the peer for tracking all active
// channels returned by the database.
func (p *peer) loadActiveChannels(chans []*channeldb.OpenChannel) error {
	for _, dbChan := range chans {
		// If the channel isn't yet open, then we don't need to process
		// it any further.
		if dbChan.IsPending {
			continue
		}

		lnChan, err := lnwallet.NewLightningChannel(p.server.lnwallet.Signer,
			p.server.chainNotifier, dbChan)
		if err != nil {
			return err
		}

		chanPoint := *dbChan.ChanID
		chanID := lnwire.NewChanIDFromOutPoint(&chanPoint)

		p.activeChanMtx.Lock()
		p.activeChannels[chanID] = lnChan
		p.activeChanMtx.Unlock()

		peerLog.Infof("peerID(%v) loaded ChannelPoint(%v)", p.id, chanPoint)

		p.server.breachArbiter.newContracts <- lnChan

		// Register this new channel link with the HTLC Switch. This is
		// necessary to properly route multi-hop payments, and forward
		// new payments triggered by RPC clients.
		sphinxDecoder := htlcswitch.NewSphinxDecoder(p.server.sphinx)
		link := htlcswitch.NewChannelLink(
			&htlcswitch.ChannelLinkConfig{
				Peer:             p,
				DecodeOnion:      sphinxDecoder.Decode,
				SettledContracts: p.server.breachArbiter.settledContracts,
				DebugHTLC:        cfg.DebugHTLC,
				Registry:         p.server.invoices,
				ForwardToSwitch:  p.server.htlcSwitch.Forward,
			}, lnChan)

		if err := p.server.htlcSwitch.AddLink(link); err != nil {
			return err
		}
	}

	return nil
}

// WaitForDisconnect waits until the peer has disconnected. A peer may be
// disconnected if the local or remote side terminating the connection, or an
// irrecoverable protocol error has been encountered.
func (p *peer) WaitForDisconnect() {
	<-p.quit

}

// Disconnect terminates the connection with the remote peer. Additionally, a
// signal is sent to the server and htlcSwitch indicating the resources
// allocated to the peer can now be cleaned up.
func (p *peer) Disconnect() {
	if !atomic.CompareAndSwapInt32(&p.disconnect, 0, 1) {
		return
	}

	peerLog.Tracef("Disconnecting %s", p)

	// Ensure that the TCP connection is properly closed before continuing.
	p.conn.Close()

	close(p.quit)

}

// String returns the string representation of this peer.
func (p *peer) String() string {
	return p.conn.RemoteAddr().String()
}

// readNextMessage reads, and returns the next message on the wire along with
// any additional raw payload.
func (p *peer) readNextMessage() (lnwire.Message, error) {
	noiseConn, ok := p.conn.(*brontide.Conn)
	if !ok {
		return nil, fmt.Errorf("brontide.Conn required to read messages")
	}

	// First we'll read the next _full_ message. We do this rather than
	// reading incrementally from the stream as the Lightning wire protocol
	// is message oriented and allows nodes to pad on additional data to
	// the message stream.
	rawMsg, err := noiseConn.ReadNextMessage()
	atomic.AddUint64(&p.bytesReceived, uint64(len(rawMsg)))
	if err != nil {
		return nil, err
	}

	// Next, create a new io.Reader implementation from the raw message,
	// and use this to decode the message directly from.
	msgReader := bytes.NewReader(rawMsg)
	nextMsg, err := lnwire.ReadMessage(msgReader, 0)
	if err != nil {
		return nil, err
	}

	// TODO(roasbeef): add message summaries
	p.logWireMessage(nextMsg, true)

	return nextMsg, nil
}

// readHandler is responsible for reading messages off the wire in series, then
// properly dispatching the handling of the message to the proper subsystem.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) readHandler() {
	var activeChanMtx sync.Mutex
	activeChanStreams := make(map[lnwire.ChannelID]struct{})

out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		nextMsg, err := p.readNextMessage()
		if err != nil {
			peerLog.Infof("unable to read message from %v: %v",
				p, err)

			switch err.(type) {
			// If this is just a message we don't yet recognize,
			// we'll continue processing as normal as this allows
			// us to introduce new messages in a forwards
			// compatible manner.
			case *lnwire.UnknownMessage:
				continue

			// If the error we encountered wasn't just a message we
			// didn't recognize, then we'll stop all processing s
			// this is a fatal error.
			default:
				break out
			}
		}

		var (
			isChanUpdate bool
			targetChan   lnwire.ChannelID
		)

		switch msg := nextMsg.(type) {
		case *lnwire.Pong:
			// When we receive a Pong message in response to our
			// last ping message, we'll use the time in which we
			// sent the ping message to measure a rough estimate of
			// round trip time.
			pingSendTime := atomic.LoadInt64(&p.pingLastSend)
			delay := (time.Now().UnixNano() - pingSendTime) / 1000
			atomic.StoreInt64(&p.pingTime, delay)

		case *lnwire.Ping:
			pongBytes := make([]byte, msg.NumPongBytes)
			p.queueMsg(lnwire.NewPong(pongBytes), nil)

		case *lnwire.SingleFundingRequest:
			p.server.fundingMgr.processFundingRequest(msg, p.addr)
		case *lnwire.SingleFundingResponse:
			p.server.fundingMgr.processFundingResponse(msg, p.addr)
		case *lnwire.SingleFundingComplete:
			p.server.fundingMgr.processFundingComplete(msg, p.addr)
		case *lnwire.SingleFundingSignComplete:
			p.server.fundingMgr.processFundingSignComplete(msg, p.addr)
		case *lnwire.FundingLocked:
			p.server.fundingMgr.processFundingLocked(msg, p.addr)
		case *lnwire.CloseRequest:
			p.remoteCloseChanReqs <- msg

		case *lnwire.Error:
			p.server.fundingMgr.processFundingError(msg, p.addr)

		// TODO(roasbeef): create ChanUpdater interface for the below
		case *lnwire.UpdateAddHTLC:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.UpdateFufillHTLC:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.UpdateFailHTLC:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.RevokeAndAck:
			isChanUpdate = true
			targetChan = msg.ChanID
		case *lnwire.CommitSig:
			isChanUpdate = true
			targetChan = msg.ChanID

		case *lnwire.ChannelUpdate,
			*lnwire.ChannelAnnouncement,
			*lnwire.NodeAnnouncement,
			*lnwire.AnnounceSignatures:

			p.server.discoverSrv.ProcessRemoteAnnouncement(msg,
				p.addr.IdentityKey)
		default:
			peerLog.Errorf("unknown message received from peer "+
				"%v", p)
		}

		if isChanUpdate {
			sendUpdate := func() {
				// Dispatch the commitment update message to the proper
				// active goroutine dedicated to this channel.
				link, err := p.server.htlcSwitch.GetLink(targetChan)
				if err != nil {
					peerLog.Errorf("recv'd update for unknown "+
						"channel %v from %v", targetChan, p)
					return
				}
				link.HandleChannelUpdate(nextMsg)
			}

			// Check the map of active channel streams, if this map
			// has an entry, then this means the channel is fully
			// open. In this case, we can send the channel update
			// directly without any further waiting.
			activeChanMtx.Lock()
			_, ok := activeChanStreams[targetChan]
			activeChanMtx.Unlock()
			if ok {
				sendUpdate()
				continue
			}

			// Otherwise, we'll launch a goroutine to synchronize
			// the processing of this message, with the opening of
			// the channel as marked by the funding manage.
			go func() {
				// Block until the channel is marked open.
				p.server.fundingMgr.waitUntilChannelOpen(targetChan)

				// Once the channel is open, we'll mark the
				// stream as active and send the update to the
				// channel. Marking the stream lets us take the
				// fast path above, skipping the check to the
				// funding manager.
				activeChanMtx.Lock()
				activeChanStreams[targetChan] = struct{}{}
				sendUpdate()
				activeChanMtx.Unlock()
			}()
		}
	}

	p.Disconnect()

	p.wg.Done()
	peerLog.Tracef("readHandler for peer %v done", p)
}

// logWireMessage logs the receipt or sending of particular wire message. This
// function is used rather than just logging the message in order to produce
// less spammy log messages in trace mode by setting the 'Curve" parameter to
// nil. Doing this avoids printing out each of the field elements in the curve
// parameters for secp256k1.
func (p *peer) logWireMessage(msg lnwire.Message, read bool) {
	switch m := msg.(type) {
	case *lnwire.RevokeAndAck:
		m.NextRevocationKey.Curve = nil
	case *lnwire.NodeAnnouncement:
		m.NodeID.Curve = nil
	case *lnwire.ChannelAnnouncement:
		m.NodeID1.Curve = nil
		m.NodeID2.Curve = nil
		m.BitcoinKey1.Curve = nil
		m.BitcoinKey2.Curve = nil
	case *lnwire.SingleFundingComplete:
		m.RevocationKey.Curve = nil
	case *lnwire.SingleFundingRequest:
		m.CommitmentKey.Curve = nil
		m.ChannelDerivationPoint.Curve = nil
	case *lnwire.SingleFundingResponse:
		m.ChannelDerivationPoint.Curve = nil
		m.CommitmentKey.Curve = nil
		m.RevocationKey.Curve = nil
	case *lnwire.FundingLocked:
		m.NextPerCommitmentPoint.Curve = nil
	}

	prefix := "readMessage from"
	if !read {
		prefix = "writeMessage to"
	}

	peerLog.Tracef(prefix+" %v: %v", p, newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
}

// writeMessage writes the target lnwire.Message to the remote peer.
func (p *peer) writeMessage(msg lnwire.Message) error {
	// Simply exit if we're shutting down.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return nil
	}

	// TODO(roasbeef): add message summaries
	p.logWireMessage(msg, false)

	// As the Lightning wire protocol is fully message oriented, we only
	// allows one wire message per outer encapsulated crypto message. So
	// we'll create a temporary buffer to write the message directly to.
	var msgPayload [lnwire.MaxMessagePayload]byte
	b := bytes.NewBuffer(msgPayload[0:0:len(msgPayload)])

	// With the temp buffer created and sliced properly (length zero, full
	// capacity), we'll now encode the message directly into this buffer.
	n, err := lnwire.WriteMessage(b, msg, 0)
	atomic.AddUint64(&p.bytesSent, uint64(n))

	// Finally, write the message itself in a single swoop.
	_, err = p.conn.Write(b.Bytes())
	return err
}

// writeHandler is a goroutine dedicated to reading messages off of an incoming
// queue, and writing them out to the wire. This goroutine coordinates with the
// queueHandler in order to ensure the incoming message queue is quickly drained.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) writeHandler() {
	defer func() {
		p.wg.Done()
		peerLog.Tracef("writeHandler for peer %v done", p)
	}()

	for {
		select {
		case outMsg := <-p.sendQueue:
			switch outMsg.msg.(type) {
			// If we're about to send a ping message, then log the
			// exact time in which we send the message so we can
			// use the delay as a rough estimate of latency to the
			// remote peer.
			case *lnwire.Ping:
				// TODO(roasbeef): do this before the write?
				// possibly account for processing within func?
				now := time.Now().UnixNano()
				atomic.StoreInt64(&p.pingLastSend, now)
			}

			// Write out the message to the socket, closing the
			// 'sentChan' if it's non-nil, The 'sentChan' allows
			// callers to optionally synchronize sends with the
			// writeHandler.
			err := p.writeMessage(outMsg.msg)
			if outMsg.sentChan != nil {
				close(outMsg.sentChan)
			}

			if err != nil {
				peerLog.Errorf("unable to write message: %v",
					err)
				p.Disconnect()
				return
			}

		case <-p.quit:
			return
		}
	}
}

// queueHandler is responsible for accepting messages from outside subsystems
// to be eventually sent out on the wire by the writeHandler.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) queueHandler() {
	defer p.wg.Done()

	pendingMsgs := list.New()
	for {
		// Before add a queue'd message our pending message queue,
		// we'll first try to aggressively empty out our pending list of
		// messaging.
		for {
			// Examine the front of the queue. If this message is
			// nil, then we've emptied out the queue and can accept
			// new messages from outside sub-systems.
			elem := pendingMsgs.Front()
			if elem == nil {
				break
			}

			select {
			case p.sendQueue <- elem.Value.(outgoinMsg):
				pendingMsgs.Remove(elem)
			case <-p.quit:
				return
			default:
				break
			}
		}

		// If there weren't any messages to send, or the writehandler
		// is still blocked, then we'll accept a new message into the
		// queue from outside sub-systems.
		select {
		case <-p.quit:
			return
		case msg := <-p.outgoingQueue:
			pendingMsgs.PushBack(msg)
		}

	}
}

// pingHandler is responsible for periodically sending ping messages to the
// remote peer in order to keep the connection alive and/or determine if the
// connection is still active.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) pingHandler() {
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	// TODO(roasbeef): make dynamic in order to create fake cover traffic
	const numPingBytes = 16

out:
	for {
		select {
		case <-pingTicker.C:
			p.queueMsg(lnwire.NewPing(numPingBytes), nil)
		case <-p.quit:
			break out
		}
	}

	p.wg.Done()
}

// PingTime returns the estimated ping time to the peer in microseconds.
func (p *peer) PingTime() int64 {
	return atomic.LoadInt64(&p.pingTime)
}

// queueMsg queues a new lnwire.Message to be eventually sent out on the
// wire.
func (p *peer) queueMsg(msg lnwire.Message, doneChan chan struct{}) {
	select {
	case p.outgoingQueue <- outgoinMsg{msg, doneChan}:
	case <-p.quit:
		return
	}
}

// ChannelSnapshots returns a slice of channel snapshots detailing all
// currently active channels maintained with the remote peer.
func (p *peer) ChannelSnapshots() []*channeldb.ChannelSnapshot {
	resp := make(chan []*channeldb.ChannelSnapshot, 1)
	p.chanSnapshotReqs <- &chanSnapshotReq{resp}
	return <-resp
}

// channelManager is goroutine dedicated to handling all requests/signals
// pertaining to the opening, cooperative closing, and force closing of all
// channels maintained with the remote peer.
//
// NOTE: This method MUST be run as a goroutine.
func (p *peer) channelManager() {
out:
	for {
		select {
		case req := <-p.chanSnapshotReqs:
			p.activeChanMtx.RLock()
			snapshots := make([]*channeldb.ChannelSnapshot, 0,
				len(p.activeChannels))
			for _, activeChan := range p.activeChannels {
				snapshot := activeChan.StateSnapshot()
				snapshots = append(snapshots, snapshot)
			}
			p.activeChanMtx.RUnlock()
			req.resp <- snapshots

		case newChanReq := <-p.newChannels:
			chanPoint := newChanReq.channel.ChannelPoint()
			chanID := lnwire.NewChanIDFromOutPoint(chanPoint)

			p.activeChanMtx.Lock()
			p.activeChannels[chanID] = newChanReq.channel
			p.activeChanMtx.Unlock()

			peerLog.Infof("New channel active ChannelPoint(%v) "+
				"with peerId(%v)", chanPoint, p.id)

			decoder := htlcswitch.NewSphinxDecoder(p.server.sphinx)
			link := htlcswitch.NewChannelLink(
				&htlcswitch.ChannelLinkConfig{
					Peer:             p,
					DecodeOnion:      decoder.Decode,
					SettledContracts: p.server.breachArbiter.settledContracts,
					DebugHTLC:        cfg.DebugHTLC,
					Registry:         p.server.invoices,
					ForwardToSwitch:  p.server.htlcSwitch.Forward,
				}, newChanReq.channel)

			err := p.server.htlcSwitch.AddLink(link)
			if err != nil {
				peerLog.Errorf("can't register new channel "+
					"link(%v) with peerId(%v)", chanPoint, p.id)
			}

			close(newChanReq.done)

		case req := <-p.localCloseChanReqs:
			p.handleLocalClose(req)

		case req := <-p.remoteCloseChanReqs:
			p.handleRemoteClose(req)

		case <-p.quit:
			break out
		}
	}

	p.wg.Done()
}

// executeCooperativeClose executes the initial phase of a user-executed
// cooperative channel close. The channel state machine is transitioned to the
// closing phase, then our half of the closing witness is sent over to the
// remote peer.
func (p *peer) executeCooperativeClose(channel *lnwallet.LightningChannel) (*chainhash.Hash, error) {
	// Shift the channel state machine into a 'closing' state. This
	// generates a signature for the closing tx, as well as a txid of the
	// closing tx itself, allowing us to watch the network to determine
	// when the remote node broadcasts the fully signed closing
	// transaction.
	sig, txid, err := channel.InitCooperativeClose()
	if err != nil {
		return nil, err
	}

	chanPoint := channel.ChannelPoint()
	peerLog.Infof("Executing cooperative closure of "+
		"ChanPoint(%v) with peerID(%v), txid=%v", chanPoint, p.id, txid)

	// With our signature for the close tx generated, send the signature to
	// the remote peer instructing it to close this particular channel
	// point.
	// TODO(roasbeef): remove encoding redundancy
	closeSig, err := btcec.ParseSignature(sig, btcec.S256())
	if err != nil {
		return nil, err
	}

	chanID := lnwire.NewChanIDFromOutPoint(chanPoint)
	closeReq := lnwire.NewCloseRequest(chanID, closeSig)
	p.queueMsg(closeReq, nil)

	return txid, nil
}

// handleLocalClose kicks-off the workflow to execute a cooperative or forced
// unilateral closure of the channel initiated by a local subsystem.
// TODO(roasbeef): if no more active channels with peer call Remove on connMgr
// with peerID
func (p *peer) handleLocalClose(req *htlcswitch.ChanClose) {
	var (
		err         error
		closingTxid *chainhash.Hash
	)

	chanID := lnwire.NewChanIDFromOutPoint(req.ChanPoint)

	p.activeChanMtx.RLock()
	channel := p.activeChannels[chanID]
	p.activeChanMtx.RUnlock()

	switch req.CloseType {
	// A type of CloseRegular indicates that the user has opted to close
	// out this channel on-chian, so we execute the cooperative channel
	// closure workflow.
	case htlcswitch.CloseRegular:
		closingTxid, err = p.executeCooperativeClose(channel)
		peerLog.Infof("Attempting cooperative close of "+
			"ChannelPoint(%v) with txid: %v", req.ChanPoint,
			closingTxid)

	// A type of CloseBreach indicates that the counterparty has breached
	// the channel therefore we need to clean up our local state.
	case htlcswitch.CloseBreach:
		peerLog.Infof("ChannelPoint(%v) has been breached, wiping "+
			"channel", req.ChanPoint)
		if err := p.WipeChannel(channel); err != nil {
			peerLog.Infof("Unable to wipe channel after detected "+
				"breach: %v", err)
			req.Err <- err
			return
		}
		return
	}
	if err != nil {
		req.Err <- err
		return
	}

	// Update the caller with a new event detailing the current pending
	// state of this request.
	req.Updates <- &lnrpc.CloseStatusUpdate{
		Update: &lnrpc.CloseStatusUpdate_ClosePending{
			ClosePending: &lnrpc.PendingUpdate{
				Txid: closingTxid[:],
			},
		},
	}

	// Finally, launch a goroutine which will request to be notified by the
	// ChainNotifier once the closure transaction obtains a single
	// confirmation.
	go func() {
		// TODO(roasbeef): add param for num needed confs
		notifier := p.server.chainNotifier
		confNtfn, err := notifier.RegisterConfirmationsNtfn(closingTxid, 1)
		if err != nil {
			req.Err <- err
			return
		}

		select {
		case height, ok := <-confNtfn.Confirmed:
			// In the case that the ChainNotifier is shutting down,
			// all subscriber notification channels will be closed,
			// generating a nil receive.
			if !ok {
				return
			}

			// The channel has been closed, remove it from any
			// active indexes, and the database state.
			peerLog.Infof("ChannelPoint(%v) is now closed at "+
				"height %v", req.ChanPoint, height.BlockHeight)
			if err := p.WipeChannel(channel); err != nil {
				req.Err <- err
				return
			}
		case <-p.quit:
			return
		}

		// Respond to the local subsystem which requested the channel
		// closure.
		req.Updates <- &lnrpc.CloseStatusUpdate{
			Update: &lnrpc.CloseStatusUpdate_ChanClose{
				ChanClose: &lnrpc.ChannelCloseUpdate{
					ClosingTxid: closingTxid[:],
					Success:     true,
				},
			},
		}

		p.server.breachArbiter.settledContracts <- req.ChanPoint
	}()
}

// handleRemoteClose completes a request for cooperative channel closure
// initiated by the remote node.
func (p *peer) handleRemoteClose(req *lnwire.CloseRequest) {
	p.activeChanMtx.RLock()
	channel, ok := p.activeChannels[req.ChanID]
	p.activeChanMtx.RUnlock()
	if !ok {
		peerLog.Errorf("unable to close channel, ChannelID(%v) is "+
			"unknown", req.ChanID)
		return
	}

	chanPoint := channel.ChannelPoint()

	// Now that we have their signature for the closure transaction, we
	// can assemble the final closure transaction, complete with our
	// signature.
	sig := req.RequesterCloseSig
	closeSig := append(sig.Serialize(), byte(txscript.SigHashAll))
	closeTx, err := channel.CompleteCooperativeClose(closeSig)
	if err != nil {
		peerLog.Errorf("unable to complete cooperative "+
			"close for ChannelPoint(%v): %v",
			chanPoint, err)
		// TODO(roasbeef): send ErrorGeneric to other side
		return
	}

	peerLog.Infof("Broadcasting cooperative close tx: %v",
		newLogClosure(func() string {
			return spew.Sdump(closeTx)
		}))

	// Finally, broadcast the closure transaction, to the network.
	if err := p.server.lnwallet.PublishTransaction(closeTx); err != nil {
		peerLog.Errorf("channel close tx from "+
			"ChannelPoint(%v) rejected: %v",
			chanPoint, err)
		// TODO(roasbeef): send ErrorGeneric to other side
		return
	}

	// TODO(roasbeef): also wait for confs before removing state
	peerLog.Infof("ChannelPoint(%v) is now closed", chanPoint)
	if err := p.WipeChannel(channel); err != nil {
		peerLog.Errorf("unable to wipe channel: %v", err)
	}

	p.server.breachArbiter.settledContracts <- chanPoint
}

// WipeChannel removes the passed channel from all indexes associated with the
// peer, and deletes the channel from the database.
func (p *peer) WipeChannel(channel *lnwallet.LightningChannel) error {
	chanID := lnwire.NewChanIDFromOutPoint(channel.ChannelPoint())

	p.activeChanMtx.Lock()
	delete(p.activeChannels, chanID)
	p.activeChanMtx.Unlock()

	// Instruct the Htlc Switch to close this link as the channel is no
	// longer active.

	if err := p.server.htlcSwitch.RemoveLink(chanID); err != nil {
		if err == htlcswitch.ErrChannelLinkNotFound {
			peerLog.Warnf("unable remove channel link with "+
				"ChannelPoint(%v): %v", chanID, err)
			return nil
		}
		return err
	}

	// Finally, we purge the channel's state from the database, leaving a
	// small summary for historical records.
	if err := channel.DeleteState(); err != nil {
		peerLog.Errorf("unable to delete ChannelPoint(%v) "+
			"from db: %v", chanID, err)
		return err
	}

	return nil
}

// handleInitMsg handles the incoming init message which contains global and
// local features vectors. If feature vectors are incompatible then disconnect.
func (p *peer) handleInitMsg(msg *lnwire.Init) error {
	localSharedFeatures, err := p.server.localFeatures.Compare(msg.LocalFeatures)
	if err != nil {
		err := errors.Errorf("can't compare remote and local feature "+
			"vectors: %v", err)
		peerLog.Error(err)
		return err
	}
	p.localSharedFeatures = localSharedFeatures

	globalSharedFeatures, err := p.server.globalFeatures.Compare(msg.GlobalFeatures)
	if err != nil {
		err := errors.Errorf("can't compare remote and global feature "+
			"vectors: %v", err)
		peerLog.Error(err)
		return err
	}
	p.globalSharedFeatures = globalSharedFeatures

	return nil
}

// sendInitMsg sends init message to remote peer which contains our currently
// supported local and global features.
func (p *peer) sendInitMsg() error {
	msg := lnwire.NewInitMessage(
		p.server.globalFeatures,
		p.server.localFeatures,
	)

	return p.writeMessage(msg)
}

// SendMessage sends message to the remote peer which represented by
// this peer.
func (p *peer) SendMessage(msg lnwire.Message) error {
	p.queueMsg(msg, nil)
	return nil
}

// ID returns the lightning network peer id.
func (p *peer) ID() [sha256.Size]byte {
	return fastsha256.Sum256(p.PubKey())
}

// PubKey returns the peer public key.
func (p *peer) PubKey() []byte {
	return p.addr.IdentityKey.SerializeCompressed()
}

// TODO(roasbeef): make all start/stop mutexes a CAS
