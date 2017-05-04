package htlcswitch

// boundedLinkChan is a simple wrapper around a channel link that bounds the
// total flow into and through the channel. Channels attached the link have a
// value which defines the max number of pending HTLC's present within the
// commitment transaction. Using this struct we establish a synchronization
// primitive that ensure we don't send additional htlcPackets to a link if
// the max limit has een reached. Once HTLC's are cleared from the commitment
// transaction, slots are freed up and more can proceed.
type boundedLinkChan struct {
	ChannelLink

	// slots is a buffered channel whose buffer is the total number of
	// outstanding HTLC's we can add to a link's commitment transaction.
	// This channel is essentially used as a semaphore.
	slots chan struct{}
}

// newBoundedChan makes a new bounder that has numSlots free slots that
// are depleted on each send until a slot is re-stored. linkChan is the
// underlying channel that will be sent upon.
func newBoundedLinkChan(numSlots uint32, link ChannelLink) *boundedLinkChan {
	b := &boundedLinkChan{
		slots:       make(chan struct{}, numSlots),
		ChannelLink: link,
	}
	for i := uint32(0); i < numSlots; i++ {
		b.restoreSlot()
	}
	return b
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
