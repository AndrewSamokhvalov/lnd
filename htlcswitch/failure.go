package htlcswitch

import (
	"bytes"

	"github.com/lightningnetwork/lightning-onion"
	"github.com/lightningnetwork/lnd/lnwire"
)

// Deobfuscator entity which is used to de-obfuscate the onion opaque reason and
// extract failure.
type Deobfuscator interface {
	// Deobfuscate function decodes the onion error failure.
	Deobfuscate(lnwire.OpaqueReason) (lnwire.Failure, error)
}

// Obfuscator entity which is used to do the initial and backward onion
// failure obfuscation.
type Obfuscator interface {
	// InitialObfuscate is used to convert the failure into opaque
	// reason, in simple implementation of this function we just decode
	// the failure, but with onion implementation we append the data with
	// hmac and obfuscate the error.
	InitialObfuscate(lnwire.Failure) (lnwire.OpaqueReason, error)

	// BackwardObfuscate is used to make the processing over onion error
	// when it moves backward to the htlc sender. In simple
	// implementation we just do nothing with data, but with onion
	// implementation we obfuscate the opaque reason.
	BackwardObfuscate(lnwire.OpaqueReason) lnwire.OpaqueReason
}

// FailureObfuscator wraps the sphinx onion obfuscator and makes it more
// lightning-network-wise by implementing the obfuscator interface.
type FailureObfuscator struct {
	*sphinx.OnionObfuscator
}

// InitialObfuscate is used by the failure sender to decode the failure and
// make the initial failure obfuscation with addition of the failure data hmac.
// NOTE: Part of the Obfuscator interface.
func (o *FailureObfuscator) InitialObfuscate(failure lnwire.Failure) (
	lnwire.OpaqueReason, error) {
	var b bytes.Buffer
	if err := lnwire.EncodeFailure(&b, failure, 0); err != nil {
		return nil, err
	}

	// Make the initial obfuscation with appending hmac.
	return o.OnionObfuscator.Obfuscate(true, b.Bytes()), nil
}

// BackwardObfuscate is used by the forwarding nodes in order to obfuscate the
// already obfuscated onion failure blob with the stream which have been
// generated with our shared secret. By obfuscating the onion failure on
// every node in the path we are adding additional step of the security and
// barrier for malware nodes to retrieve valuable information.
// NOTE: Part of the Obfuscator interface.
func (o *FailureObfuscator) BackwardObfuscate(
	reason lnwire.OpaqueReason) lnwire.OpaqueReason {
	return o.OnionObfuscator.Obfuscate(false, reason)
}

// A compile time check to ensure FailureObfuscator implements the
// Obfuscator interface.
var _ Obfuscator = (*FailureObfuscator)(nil)

// FailureDeobfuscator wraps the sphinx onion de-obfuscator and makes it more
// lightning-network-wise by operating with the lnwire structures which
// represent the onion failures rather than blobs of data.
type FailureDeobfuscator struct {
	*sphinx.OnionDeobfuscator
}

// Deobfuscate decodes the obfuscated onion failure.
// NOTE: Part of the Obfuscator interface.
func (o *FailureDeobfuscator) Deobfuscate(obfuscatedData lnwire.OpaqueReason) (
	lnwire.Failure, error) {
	_, failureData, err := o.OnionDeobfuscator.Deobfuscate(obfuscatedData)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(failureData)
	return lnwire.DecodeFailure(r, 0)
}

// A compile time check to ensure FailureDeobfuscator implements the
// Deobfuscator interface.
var _ Deobfuscator = (*FailureDeobfuscator)(nil)
