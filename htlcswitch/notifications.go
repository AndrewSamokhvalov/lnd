package htlcswitch

import (
	"sync"

	"container/list"

	"sync/atomic"

	"time"

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
	return client
}

func init() {
	client = &PaymentNotificationsClient{
		listeners:     make(map[lnwire.ShortChannelID][]*Listener),
		outgoingQueue: make(chan pendingNotification),
		control:       make(chan interface{}),
		quit:          make(chan struct{}),
	}
	client.Start()
}

// closeRequest...
type closeRequest lnwire.ShortChannelID

// unregisterRequest...
type unregisterRequest *Listener

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
	chanID        lnwire.ShortChannelID
	Notifications chan interface{}

	Stop func()
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
		// In order to not work in a blank wait for at least one object to be
		// added in the pending queue.
		if pendingQueue.Len() == 0 {
			select {
			case ntf := <-c.outgoingQueue:
				pendingQueue.PushBack(ntf)
			case <-c.quit:
				return
			}
		}

		// Examine the front of the queue, at this point we have an object
		// which should be sent to the listener.
		elem := pendingQueue.Front()
		pn := elem.Value.(pendingNotification)

		select {
		case pn.listener.Notifications <- pn.notification:
			pendingQueue.Remove(elem)

		case ntf := <-c.outgoingQueue:
			pendingQueue.PushBack(ntf)

		case <-c.quit:
			return
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
					chanID:        r.chanID,
					Notifications: make(chan interface{}),
				}

				listener.Stop = func() {
					select {
					case c.control <- (unregisterRequest)(listener):
					case <-c.quit:
					}
				}

				c.listeners[r.chanID] = append(c.listeners[r.chanID], listener)
				r.done <- listener

			case notificationRequest:
				// Create pending notification for all notification listeners
				// for this channel.
				for _, listener := range c.listeners[r.chanID] {
					// Create pending notification and attach the listener so
					// that we could send the notification when lister will
					// be available.
					c.outgoingQueue <- pendingNotification{
						notification: r.notification,
						listener:     listener,
					}
				}
			case unregisterRequest:
				l := (*Listener)(r)

				listeners := c.listeners[r.chanID]
				for i, listener := range listeners {
					if listener == l {
						// Delete without preserving order
						// Google: Golang slice tricks
						listeners[i] = listeners[len(listeners)-1]
						listeners[len(listeners)-1] = nil
						c.listeners[r.chanID] = listeners[:len(listeners)-1]
						break
					}
				}

				// ...
				l.Notifications = nil

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
	// Time...
	Time time.Time

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
	// Time...
	Time time.Time

	// Amount...
	Amount btcutil.Amount

	// PaymentHash...
	PaymentHash lnwallet.PaymentHash

	// EarnedFee...
	EarnedFee btcutil.Amount
}
