package htlcswitch

import (
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcutil"
	"github.com/lightningnetwork/lnd/lnwallet"
)

type mockServer struct {
	t           *testing.T
	name        string
	messages    chan lnwire.Message
	quit        chan bool
	id          []byte
	htlcSwitch  *Switch
	wg          sync.WaitGroup
	recordFuncs []func(lnwire.Message)
}

var _ Peer = (*mockServer)(nil)

func newMockServer(t *testing.T, name string) *mockServer {
	return &mockServer{
		t:           t,
		id:          []byte(name),
		name:        name,
		messages:    make(chan lnwire.Message, 50),
		quit:        make(chan bool),
		htlcSwitch:  New(Config{}),
		recordFuncs: make([]func(lnwire.Message), 0),
	}
}

func (s *mockServer) Start() error {
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

// messageInterceptor is function that handles the incoming peer messages and
// may decide should we handle it or not.
type messageInterceptor func(m lnwire.Message)

// Record is used to set the function which will be triggered when new
// lnwire message was received.
func (s *mockServer) record(f messageInterceptor) {
	s.recordFuncs = append(s.recordFuncs, f)
}

func (s *mockServer) SendMessage(message lnwire.Message) error {
	select {
	case s.messages <- message:
	case <-s.quit:
	}

	return nil
}

func (s *mockServer) readHandler(message lnwire.Message) error {
	var targetChan lnwire.ChannelID

	switch msg := message.(type) {
	case *lnwire.UpdateAddHTLC:
		targetChan = msg.ChanID
	case *lnwire.UpdateFufillHTLC:
		targetChan = msg.ChanID
	case *lnwire.UpdateFailHTLC:
		targetChan = msg.ChanID
	case *lnwire.RevokeAndAck:
		targetChan = msg.ChanID
	case *lnwire.CommitSig:
		targetChan = msg.ChanID
	default:
		return errors.New("unknown message type")
	}

	// Dispatch the commitment update message to the proper
	// channel link dedicated to this channel.
	link, err := s.htlcSwitch.GetLink(targetChan)
	if err != nil {
		return err
	}

	link.HandleChannelUpdate(message)
	return nil
}

func (s *mockServer) ID() [sha256.Size]byte {
	return [sha256.Size]byte{}
}

func (s *mockServer) PubKey() []byte {
	return s.id
}

func (s *mockServer) Disconnect() {
	s.t.Fatalf("server %v was disconnected", s.name)
}

func (s *mockServer) WipeChannel(*lnwallet.LightningChannel) error {
	return nil
}

func (s *mockServer) Stop() {
	close(s.quit)
}

func (s *mockServer) Wait() {
	s.wg.Wait()

	s.htlcSwitch.Stop()
}

func (s *mockServer) String() string {
	return string(s.id)
}

type mockChannelLink struct {
	chanID  lnwire.ChannelID
	peer    Peer
	packets chan *htlcPacket
}

func newMockChannelLink(chanID lnwire.ChannelID,
	peer Peer) *mockChannelLink {
	return &mockChannelLink{
		chanID:  chanID,
		packets: make(chan *htlcPacket, 1),
		peer:    peer,
	}
}

func (f *mockChannelLink) HandleSwitchPacket(packet *htlcPacket) {
	f.packets <- packet
}

func (f *mockChannelLink) HandleChannelUpdate(lnwire.Message) {
}

func (f *mockChannelLink) Stats() (uint64, btcutil.Amount, btcutil.Amount) {
	return 0, 0, 0
}

func (f *mockChannelLink) ChanID() lnwire.ChannelID  { return f.chanID }
func (f *mockChannelLink) Bandwidth() btcutil.Amount { return 99999999 }
func (f *mockChannelLink) Peer() Peer                { return f.peer }
func (f *mockChannelLink) Start() error              { return nil }
func (f *mockChannelLink) Stop()                     {}

var _ ChannelLink = (*mockChannelLink)(nil)
