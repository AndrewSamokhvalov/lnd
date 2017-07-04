package htlcswitch

import (
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lnwire"
)

func TestPaymentNotificationsClientSingleton(t *testing.T) {
	c1 := getNotificationClient()
	c2 := getNotificationClient()

	if c1 != c2 {
		t.Fatal("clients are different")
	}
}

func TestPaymentNotificationsClient(t *testing.T) {
	client := getNotificationClient()
	client.Start()
	defer client.Stop()

	chanID := lnwire.ShortChannelID{BlockHeight: 1}
	listener, err := client.Register(chanID)
	if err != nil {
		t.Fatalf("unable to register listener: %v", err)
	}

	ntf1 := struct{}{}
	client.Notify(chanID, ntf1)

	select {
	case ntf2 := <-listener.notifications:
		if ntf1 != ntf2 {
			t.Fatal("notification are different")
		}
	case <-time.After(time.Second):
		t.Fatal("notification haven't been received")
	}
}
