package main

import (
	"fmt"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

// nodeSigner is an implementation of the MessageSigner interface backed by the
// identity private key of running lnd node.
type nodeSigner struct {
	privKey *btcec.PrivateKey
}

// newNodeSigner creates a new instance of the nodeSigner backed by the target
// private key.
func newNodeSigner(key *btcec.PrivateKey) *nodeSigner {
	return &nodeSigner{
		privKey: key,
	}
}

// SignMessage signs a double-sha256 digest of the passed msg under the
// resident node's private key. If the target public key is _not_ the node's
// private key, then an error will be returned.
func (n *nodeSigner) SignMessage(pubKey *btcec.PublicKey,
	msg []byte) (*btcec.Signature, error) {

	// If this isn't our identity public key, then we'll exit early with an
	// error as we can't sign with this key.
	if !pubKey.IsEqual(n.privKey.PubKey()) {
		return nil, fmt.Errorf("unknown public key")
	}

	// Otherwise, we'll sign the dsha256 of the target message.
	digest := chainhash.DoubleHashB(msg)
	sign, err := n.privKey.Sign(digest)
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

	return sign, nil
}

// SignCompact signs a double-sha256 digest of the msg parameter under the
// resident node's private key. The returned signature is a pubkey-recoverable
// signature.
func (n *nodeSigner) SignCompact(msg []byte) ([]byte, error) {

	// Otherwise, we'll sign the dsha256 of the target message.
	digest := chainhash.DoubleHashB(msg)

	// Should the signature reference a compressed public key or not.
	isCompressedKey := true

	// btcec.SignCompact returns a pubkey-recoverable signature
	sig, err := btcec.SignCompact(btcec.S256(), n.privKey, digest,
		isCompressedKey)
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

	return sig, nil
}

// A compile time check to ensure that nodeSigner implements the MessageSigner
// interface.
var _ lnwallet.MessageSigner = (*nodeSigner)(nil)
