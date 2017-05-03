package htlcswitch

// boundedLinkChan is a simple wrapper around a link's communication channel
// that bounds the total flow into and through the channel. Channels attached
// the link have a value which defines the max number of pending HTLC's present
// within the commitment transaction. Using this struct we establish a
// synchronization primitive that ensure we don't send additional htlcPackets
// to a link if the max limit has een reached. Once HTLC's are cleared from the
// commitment transaction, slots are freed up and more can proceed.
type boundedLinkChan struct {
	// slots is a buffered channel whose buffer is the total number of
	// outstanding HTLC's we can add to a link's commitment transaction.
	// This channel is essentially used as a semaphore.
	slots chan struct{}

	// linkChan is a channel that is connected to the channel state machine
	// for a link. The switch will send adds, settles, and cancels over
	// this channel.
	linkChan chan *htlcPacket
}

// newBoundedChan makes a new boundedLinkChan that has numSlots free slots that
// are depleted on each send until a slot is re-stored. linkChan is the
// underlying channel that will be sent upon.
func newBoundedLinkChan(numSlots uint32,
	linkChan chan *htlcPacket) *boundedLinkChan {

	b := &boundedLinkChan{
		slots:    make(chan struct{}, numSlots),
		linkChan: linkChan,
	}

	b.restoreSlots(numSlots)
	return b
}

// sendAndConsume sends a packet to the linkChan and consumes a single token in
// the process.
//
// TODO(roasbeef): add error fall through case?
func (b *boundedLinkChan) sendAndConsume(pkt *htlcPacket) {
	<-b.slots
	b.linkChan <- pkt
}

// sendAndRestore sends a packet to the linkChan and consumes a single token in
// the process. This method is called when the switch sends either a cancel or
// settle HTLC message to the link.
func (b *boundedLinkChan) sendAndRestore(pkt *htlcPacket) {
	b.linkChan <- pkt
	b.slots <- struct{}{}
}

// consumeSlot consumes a single slot from the bounded channel. This method is
// called once the switch receives a new htlc add message from a link right
// before forwarding it to the next hop.
func (b *boundedLinkChan) consumeSlot() {
	<-b.slots
}

// restoreSlot restores a single slots to the bounded channel. This method is
// called once the switch receives an HTLC cancel or settle from a link.
func (b *boundedLinkChan) restoreSlot() {
	b.slots <- struct{}{}
}

// restoreSlots adds numSlots additional slots to the bounded channel.
func (b *boundedLinkChan) restoreSlots(numSlots uint32) {
	for i := uint32(0); i < numSlots; i++ {
		b.slots <- struct{}{}
	}
}
