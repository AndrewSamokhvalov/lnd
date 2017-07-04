package htlcswitch

import (
	"sync"

	"container/list"

	"sync/atomic"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcutil"
)

// client is a singleton payment notification client, which is used inside
// all channel links.
var client *PaymentNotificationsClient

// once is used to make only one operation of notification client initialisation.
var once sync.Once

// getNotificationClient...
func getNotificationClient() *PaymentNotificationsClient {
	once.Do(func() {
		client = &PaymentNotificationsClient{
			listeners:     make(map[lnwire.ShortChannelID][]*Listener),
			outgoingQueue: make(chan pendingNotification),
			control:       make(chan interface{}),
			quit:          make(chan struct{}),
		}
	})
	return client
}

// closeRequest...
type closeRequest lnwire.ShortChannelID

// unregisterRequest...
type unregisterRequest lnwire.ShortChannelID

// registerRequest...
type registerRequest struct {
	chanID lnwire.ShortChannelID
	done   chan *Listener
}

// notificationRequest...
type notificationRequest struct {
	notification interface{}
	chanID       lnwire.ShortChannelID
}

// pendingNotification...
type pendingNotification struct {
	notification interface{}
	listener     *Listener
}

// Listener...
type Listener struct {
	stopped       chan struct{}
	notifications chan interface{}
}

// Stop...
func (l *Listener) Stop() {
	close(l.stopped)
	close(l.notifications)
}

// PaymentNotificationsClient...
type PaymentNotificationsClient struct {
	started  int32
	shutdown int32
	quit     chan struct{}
	wg       sync.WaitGroup

	// outgoingQueue is a buffered channel which allows second/third party
	// objects to queue messages to be sent out on the wire.
	outgoingQueue chan pendingNotification

	// listeners...
	listeners map[lnwire.ShortChannelID][]*Listener

	// control...
	control chan interface{}
}

// Start...
func (c *PaymentNotificationsClient) Start() {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		log.Warn("Payment notification client already started")
		return
	}

	log.Infof("Payment notification client is starting")

	c.wg.Add(1)
	go c.queueHandler()

	c.wg.Add(1)
	go c.controlHandler()

}

// Stop..
func (c *PaymentNotificationsClient) Stop() {
	if !atomic.CompareAndSwapInt32(&c.shutdown, 0, 1) {
		log.Warn("Payment notification client already shutted down")
		return
	}

	log.Infof("Payment notification client is shutting down")

	close(c.quit)
	c.wg.Wait()
}

// queueHandler is responsible for accepting messages from outside subsystems
// to be eventually sent out on the wire by the writeHandler.
//
// NOTE: This method MUST be run as a goroutine.
func (c *PaymentNotificationsClient) queueHandler() {
	defer c.wg.Done()

	pendingQueue := list.New()
	for {
		// Before add a queue'd message our pending message queue,
		// we'll first try to aggressively empty out our pending list of
		// messaging.
		for {
			// Examine the front of the queue. If this message is
			// nil, then we've emptied out the queue and can accept
			// new messages from outside sub-systems.
			elem := pendingQueue.Front()
			if elem == nil {
				break
			}
			pn := elem.Value.(pendingNotification)

			select {
			case pn.listener.notifications <- pn.notification:
				pendingQueue.Remove(elem)

			// If lister was stopped or channel have been closed and listener
			// have been unregistered, than remove notification from processing.
			case <-pn.listener.stopped:
				pendingQueue.Remove(elem)
			case <-c.quit:
				return
			default:
				break
			}
		}

		// If there weren't any messages to send, or the writehandler
		// is still blocked, then we'll accept a new message into the
		// queue from outside sub-systems.
		select {
		case <-c.quit:
			return
		case ntf := <-c.outgoingQueue:
			pendingQueue.PushBack(ntf)
		}

	}
}

// controlHandler...
//
// NOTE: This method MUST be run as a goroutine.
func (c *PaymentNotificationsClient) controlHandler() {
	defer c.wg.Done()

	for {
		select {
		case request := <-c.control:
			switch r := request.(type) {
			case registerRequest:
				listener := &Listener{
					stopped:       make(chan struct{}),
					notifications: make(chan interface{}),
				}
				c.listeners[r.chanID] = append(c.listeners[r.chanID], listener)
				r.done <- listener

			case notificationRequest:
				// Create pending notification for all notification listeners
				// for this channel.
				for i, listener := range c.listeners[r.chanID] {

					// Check that lister haven't been stopped, and if
					// been than remove it from the list and skip notification.
					select {
					case <-listener.stopped:
						listeners := c.listeners[r.chanID]
						// Delete without preserving order
						// Google: Golang slice tricks
						listeners[i] = listeners[len(listeners)-1]
						listeners[len(listeners)-1] = nil
						c.listeners[r.chanID] = listeners[:len(listeners)-1]
						continue
					default:
					}

					// Create pending notification and attach the listener so
					// that we could send the notification when lister will
					// be available.
					c.outgoingQueue <- pendingNotification{
						notification: r.notification,
						listener:     listener,
					}
				}

			case closeRequest:
				chanID := lnwire.ShortChannelID(r)
				for _, listener := range c.listeners[chanID] {
					listener.Stop()
				}
				delete(c.listeners, chanID)
			}
		case <-c.quit:
			return
		}
	}
}

// Notify takes the notification us input and sends it to all registered
// payment notification listeners.
func (c *PaymentNotificationsClient) Notify(chanID lnwire.ShortChannelID,
	notification interface{}) {
	select {
	case c.control <- notificationRequest{
		chanID:       chanID,
		notification: notification,
	}:
	case <-c.quit:
	}
}

// Close...
func (c *PaymentNotificationsClient) Close(chanID lnwire.ShortChannelID) {
	select {
	case c.control <- (closeRequest)(chanID):
	case <-c.quit:
	}
}

// Register...
func (c *PaymentNotificationsClient) Register(chanID lnwire.ShortChannelID) (
	*Listener, error) {
	done := make(chan *Listener)

	select {
	case c.control <- registerRequest{
		chanID: chanID,
		done:   done,
	}:
	case <-c.quit:
	}

	select {
	case listener := <-done:
		return listener, nil
	case <-c.quit:
	}

	return nil, errors.New("payment notification client shutted down")
}

// PaymentNotification...
type PaymentNotification struct {
	// SenderPubKey...
	// NOTE: Optional field, which is populated only
	SenderPubKey *btcec.PublicKey

	// SenderDescription...
	// NOTE: Optional field, which is populated only
	SenderDescription []byte

	// PaymentHash...
	PaymentHash lnwallet.PaymentHash

	// Amount...
	Amount btcutil.Amount
}

// ForwardNotification...
type ForwardNotification struct {
	// Amount...
	Amount btcutil.Amount

	// PaymentHash...
	PaymentHash lnwallet.PaymentHash

	// HTLCFee...
	HTLCFee btcutil.Amount
}
