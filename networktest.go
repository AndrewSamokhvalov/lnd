package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"

	"bytes"

	"sync/atomic"

	"io"

	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/rpctest"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcrpcclient"
	"github.com/roasbeef/btcutil"
)

var (
	// numActiveNodes is the number of active nodes within the test network.
	numActiveNodes = 0

	// defaultNodePort is the initial p2p port which will be used by the
	// first created lightning node to listen on for incoming p2p
	// connections.  Subsequent allocated ports for future lighting nodes
	// instances will be monotonically increasing odd numbers calculated as
	// such: defaultP2pPort + (2 * harness.nodeNum).
	defaultNodePort = 19555

	// defaultClientPort is the initial rpc port which will be used by the
	// first created lightning node to listen on for incoming rpc
	// connections. Subsequent allocated ports for future rpc harness
	// instances will be monotonically increasing even numbers calculated
	// as such: defaultP2pPort + (2 * harness.nodeNum).
	defaultClientPort = 19556

	harnessNetParams = &chaincfg.SimNetParams
)

// generateListeningPorts returns two strings representing ports to listen on
// designated for the current lightning network test. If there haven't been any
// test instances created, the default ports are used. Otherwise, in order to
// support multiple test nodes running at once, the p2p and rpc port are
// incremented after each initialization.
func generateListeningPorts() (int, int) {
	var p2p, rpc int
	if numActiveNodes == 0 {
		p2p = defaultNodePort
		rpc = defaultClientPort
	} else {
		p2p = defaultNodePort + (2 * numActiveNodes)
		rpc = defaultClientPort + (2 * numActiveNodes)
	}

	return p2p, rpc
}

// lightningNode represents an instance of lnd running within our test network
// harness. Each lightningNode instance also fully embedds an RPC client in
// order to pragmatically drive the node.
type lightningNode struct {
	cfg *config

	rpcAddr string
	p2pAddr string
	rpcCert []byte

	nodeID int

	// PubKey is the serialized compressed identity public key of the node.
	// This field will only be populated once the node itself has been
	// started via the start() method.
	PubKey    [33]byte
	PubKeyStr string

	cmd     *exec.Cmd
	pidFile string

	// processExit is a channel that's closed once it's detected that the
	// process this instance of lightningNode is bound to has exited.
	processExit chan struct{}

	extraArgs []string

	lnrpc.LightningClient
}

// newLightningNode creates a new test lightning node instance from the passed
// rpc config and slice of extra arguments.
func newLightningNode(rpcConfig *btcrpcclient.ConnConfig, lndArgs []string) (*lightningNode, error) {
	var err error

	cfg := &config{
		RPCHost: rpcConfig.Host,
		RPCUser: rpcConfig.User,
		RPCPass: rpcConfig.Pass,
	}

	nodeNum := numActiveNodes
	cfg.DataDir, err = ioutil.TempDir("", "lndtest-data")
	if err != nil {
		return nil, err
	}
	cfg.LogDir, err = ioutil.TempDir("", "lndtest-log")
	if err != nil {
		return nil, err
	}

	cfg.PeerPort, cfg.RPCPort = generateListeningPorts()

	numActiveNodes++

	return &lightningNode{
		cfg:         cfg,
		p2pAddr:     net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.PeerPort)),
		rpcAddr:     net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.RPCPort)),
		rpcCert:     rpcConfig.Certificates,
		nodeID:      nodeNum,
		processExit: make(chan struct{}),
		extraArgs:   lndArgs,
	}, nil
}

// genArgs generates a slice of command line arguments from the lightningNode's
// current config struct.
func (l *lightningNode) genArgs() []string {
	var args []string

	encodedCert := hex.EncodeToString(l.rpcCert)
	args = append(args, fmt.Sprintf("--btcdhost=%v", l.cfg.RPCHost))
	args = append(args, fmt.Sprintf("--rpcuser=%v", l.cfg.RPCUser))
	args = append(args, fmt.Sprintf("--rpcpass=%v", l.cfg.RPCPass))
	args = append(args, fmt.Sprintf("--rawrpccert=%v", encodedCert))
	args = append(args, fmt.Sprintf("--rpcport=%v", l.cfg.RPCPort))
	args = append(args, fmt.Sprintf("--peerport=%v", l.cfg.PeerPort))
	args = append(args, fmt.Sprintf("--logdir=%v", l.cfg.LogDir))
	args = append(args, fmt.Sprintf("--datadir=%v", l.cfg.DataDir))
	args = append(args, fmt.Sprintf("--simnet"))

	if l.extraArgs != nil {
		args = append(args, l.extraArgs...)
	}

	return args
}

// start launches a new process running lnd. Additionally, the PID of the
// launched process is saved in order to possibly kill the process forcibly
// later.
func (l *lightningNode) start(lndError chan error) error {
	args := l.genArgs()

	l.cmd = exec.Command("lnd", args...)

	// Redirect stderr output to buffer
	var errb bytes.Buffer
	l.cmd.Stderr = &errb

	if err := l.cmd.Start(); err != nil {
		return err
	}

	// Launch a new goroutine which that bubbles up any potential fatal
	// process errors to the goroutine running the tests.
	go func() {
		if err := l.cmd.Wait(); err != nil {
			lndError <- errors.New(errb.String())
		}

		// Signal any onlookers that this process has exited.
		close(l.processExit)
	}()

	pid, err := os.Create(filepath.Join(l.cfg.DataDir,
		fmt.Sprintf("%v.pid", l.nodeID)))
	if err != nil {
		return err
	}
	l.pidFile = pid.Name()
	if _, err = fmt.Fprintf(pid, "%v\n", l.cmd.Process.Pid); err != nil {
		return err
	}
	if err := pid.Close(); err != nil {
		return err
	}

	opts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithTimeout(time.Second * 20),
	}
	conn, err := grpc.Dial(l.rpcAddr, opts...)
	if err != nil {
		return err
	}

	l.LightningClient = lnrpc.NewLightningClient(conn)

	// Obtain the lnid of this node for quick identification purposes.
	ctxb := context.Background()
	info, err := l.GetInfo(ctxb, &lnrpc.GetInfoRequest{})
	if err != nil {
		return err
	}

	l.PubKeyStr = info.IdentityPubkey

	pubkey, err := hex.DecodeString(info.IdentityPubkey)
	if err != nil {
		return err
	}
	copy(l.PubKey[:], pubkey)

	return nil
}

// cleanup cleans up all the temporary files created by the node's process.
func (l *lightningNode) cleanup() error {
	dirs := []string{
		l.cfg.LogDir,
		l.cfg.DataDir,
	}

	var err error
	for _, dir := range dirs {
		if err = os.RemoveAll(dir); err != nil {
			log.Printf("Cannot remove dir %s: %v", dir, err)
		}
	}
	return err
}

// stop attempts to stop the active lnd process.
func (l *lightningNode) stop() error {
	// We should skip node stop in case:
	// - start of the node wasn't initiated
	// - process wasn't spawned
	// - process already finished
	processFinished := l.cmd.ProcessState != nil &&
		l.cmd.ProcessState.Exited()
	if l.cmd == nil || l.cmd.Process == nil || processFinished {
		return nil
	}

	if runtime.GOOS == "windows" {
		return l.cmd.Process.Signal(os.Kill)
	}
	return l.cmd.Process.Signal(os.Interrupt)
}

// restart attempts to restart a lightning node by shutting it down cleanly,
// then restarting the process. This function is fully blocking. Upon restart,
// the RPC connection to the node will be re-attempted, continuing iff the
// connection attempt is successful. Additionally, if a callback is passed, the
// closure will be executed after the node has been shutdown, but before the
// process has been started up again.
func (l *lightningNode) restart(errChan chan error, callback func() error) error {
	if err := l.stop(); err != nil {
		return nil
	}

	<-l.processExit

	l.processExit = make(chan struct{})

	if callback != nil {
		if err := callback(); err != nil {
			return err
		}
	}

	return l.start(errChan)
}

// shutdown stops the active lnd process and clean up any temporary directories
// created along the way.
func (l *lightningNode) shutdown() error {
	if err := l.stop(); err != nil {
		return err
	}
	if err := l.cleanup(); err != nil {
		return err
	}
	return nil
}

// networkHarness is an integration testing harness for the lightning network.
// The harness by default is created with two active nodes on the network:
// Alice and Bob.
type networkHarness struct {
	rpcConfig btcrpcclient.ConnConfig
	netParams *chaincfg.Params
	Miner     *rpctest.Harness

	activeNodes map[int]*lightningNode

	// Alice and Bob are the initial seeder nodes that are automatically
	// created to be the initial participants of the test network.
	Alice *lightningNode
	Bob   *lightningNode

	seenTxns      chan chainhash.Hash
	watchRequests chan *watchRequest

	// Channel for transmitting stderr output from failed lightning node
	// to main process.
	lndErrorChan chan error

	sync.Mutex
}

// newNetworkHarness creates a new network test harness.
// TODO(roasbeef): add option to use golang's build library to a binary of the
// current repo. This'll save developers from having to manually `go install`
// within the repo each time before changes
func newNetworkHarness() (*networkHarness, error) {
	return &networkHarness{
		activeNodes:   make(map[int]*lightningNode),
		seenTxns:      make(chan chainhash.Hash),
		watchRequests: make(chan *watchRequest),
		lndErrorChan:  make(chan error),
	}, nil
}

// InitializeSeedNodes initialized alice and bob nodes given an already
// running instance of btcd's rpctest harness and extra command line flags,
// which should be formatted properly - "--arg=value".
func (n *networkHarness) InitializeSeedNodes(r *rpctest.Harness, lndArgs []string) error {
	nodeConfig := r.RPCConfig()

	n.netParams = r.ActiveNet
	n.Miner = r
	n.rpcConfig = nodeConfig

	var err error
	n.Alice, err = newLightningNode(&nodeConfig, lndArgs)
	if err != nil {
		return err
	}
	n.Bob, err = newLightningNode(&nodeConfig, lndArgs)
	if err != nil {
		return err
	}

	n.activeNodes[n.Alice.nodeID] = n.Alice
	n.activeNodes[n.Bob.nodeID] = n.Bob

	return err
}

// ProcessErrors returns a channel used for reporting any fatal process errors.
// If any of the active nodes within the harness' test network incur a fatal
// error, that error is sent over this channel.
func (n *networkHarness) ProcessErrors() chan error {
	return n.lndErrorChan
}

// fakeLogger is a fake grpclog.Logger implementation. This is used to stop
// grpc's logger from printing directly to stdout.
type fakeLogger struct{}

func (f *fakeLogger) Fatal(args ...interface{})                 {}
func (f *fakeLogger) Fatalf(format string, args ...interface{}) {}
func (f *fakeLogger) Fatalln(args ...interface{})               {}
func (f *fakeLogger) Print(args ...interface{})                 {}
func (f *fakeLogger) Printf(format string, args ...interface{}) {}
func (f *fakeLogger) Println(args ...interface{})               {}

// SetUp starts the initial seeder nodes within the test harness. The initial
// node's wallets will be funded wallets with ten 1 BTC outputs each. Finally
// rpc clients capable of communicating with the initial seeder nodes are
// created.
func (n *networkHarness) SetUp() error {
	// Swap out grpc's default logger with out fake logger which drops the
	// statements on the floor.
	grpclog.SetLogger(&fakeLogger{})

	// Start the initial seeder nodes within the test network, then connect
	// their respective RPC clients.
	var wg sync.WaitGroup
	errChan := make(chan error, 2)
	wg.Add(2)
	go func() {
		var err error
		defer wg.Done()
		if err = n.Alice.start(n.lndErrorChan); err != nil {
			errChan <- err
			return
		}
	}()
	go func() {
		var err error
		defer wg.Done()
		if err = n.Bob.start(n.lndErrorChan); err != nil {
			errChan <- err
			return
		}
	}()
	wg.Wait()
	select {
	case err := <-errChan:
		return err
	default:
	}

	// Load up the wallets of the seeder nodes with 10 outputs of 1 BTC
	// each.
	ctxb := context.Background()
	addrReq := &lnrpc.NewAddressRequest{
		Type: lnrpc.NewAddressRequest_WITNESS_PUBKEY_HASH,
	}
	clients := []lnrpc.LightningClient{n.Alice, n.Bob}
	for _, client := range clients {
		for i := 0; i < 10; i++ {
			resp, err := client.NewAddress(ctxb, addrReq)
			if err != nil {
				return err
			}
			addr, err := btcutil.DecodeAddress(resp.Address, n.netParams)
			if err != nil {
				return err
			}
			addrScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return err
			}

			output := &wire.TxOut{
				PkScript: addrScript,
				Value:    btcutil.SatoshiPerBitcoin,
			}
			if _, err := n.Miner.SendOutputs([]*wire.TxOut{output}, 30); err != nil {
				return err
			}
		}
	}

	// We generate several blocks in order to give the outputs created
	// above a good number of confirmations.
	if _, err := n.Miner.Node.Generate(10); err != nil {
		return err
	}

	// Finally, make a connection between both of the nodes.
	if err := n.ConnectNodes(ctxb, n.Alice, n.Bob); err != nil {
		return err
	}

	// Now block until both wallets have fully synced up.
	expectedBalance := btcutil.Amount(btcutil.SatoshiPerBitcoin * 10).ToBTC()
	balReq := &lnrpc.WalletBalanceRequest{}
	balanceTicker := time.Tick(time.Millisecond * 50)
out:
	for {
		select {
		case <-balanceTicker:
			aliceResp, err := n.Alice.WalletBalance(ctxb, balReq)
			if err != nil {
				return err
			}
			bobResp, err := n.Bob.WalletBalance(ctxb, balReq)
			if err != nil {
				return err
			}

			if aliceResp.Balance == expectedBalance &&
				bobResp.Balance == expectedBalance {
				break out
			}
		case <-time.After(time.Second * 30):
			return fmt.Errorf("balances not synced after deadline")
		}
	}

	// Now that the initial test network has been initialized, launch the
	// network wather.
	go n.networkWatcher()

	return nil
}

// TearDownAll tears down all active nodes within the test lightning network.
func (n *networkHarness) TearDownAll() error {
	for _, node := range n.activeNodes {
		if err := node.shutdown(); err != nil {
			return err
		}
	}

	return nil
}

// NewNode fully initializes a returns a new lightningNode binded to the
// current instance of the network harness. The created node is running, but
// not yet connected to other nodes within the network.
func (n *networkHarness) NewNode(extraArgs []string) (*lightningNode, error) {
	n.Lock()
	defer n.Unlock()

	node, err := newLightningNode(&n.rpcConfig, extraArgs)
	if err != nil {
		return nil, err
	}

	if err := node.start(n.lndErrorChan); err != nil {
		return nil, err
	}

	n.activeNodes[node.nodeID] = node

	return node, nil
}

// ConnectNodes establishes an encrypted+authenticated p2p connection from node
// a towards node b.
func (n *networkHarness) ConnectNodes(ctx context.Context, a, b *lightningNode) error {
	bobInfo, err := b.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	if err != nil {
		return err
	}

	req := &lnrpc.ConnectPeerRequest{
		Addr: &lnrpc.LightningAddress{
			Pubkey: bobInfo.IdentityPubkey,
			Host:   b.p2pAddr,
		},
	}
	if _, err := a.ConnectPeer(ctx, req); err != nil {
		return err
	}

	return nil
}

// RestartNode  attempts to restart a lightning node by shutting it down
// cleanly, then restarting the process. This function is fully blocking. Upon
// restart, the RPC connection to the node will be re-attempted, continuing iff
// the connection attempt is successful. If the callback parameter is non-nil,
// then the function will be executed after the node shuts down, but *before*
// the process has been started up again.
//
// This method can be useful when testing edge cases such as a node broadcast
// and invalidated prior state, or persistent state recovery, simulating node
// crashes, etc.
func (n *networkHarness) RestartNode(node *lightningNode, callback func() error) error {
	return node.restart(n.lndErrorChan, callback)
}

// TODO(roasbeef): add a WithChannel higher-order function?
//  * python-like context manager w.r.t using a channel within a test
//  * possibly  adds more funds to the target wallet if the funds are not
//    enough

// watchRequest encapsulates a request to the harness' network watcher to
// dispatch a notification once a transaction with the target txid is seen
// within the test network.
type watchRequest struct {
	txid      chainhash.Hash
	eventChan chan struct{}
}

// networkWatcher is a goroutine which accepts async notification requests for
// the broadcast of a target transaction, and then dispatches the transaction
// once its seen on the network.
func (n *networkHarness) networkWatcher() {
	seenTxns := make(map[chainhash.Hash]struct{})
	clients := make(map[chainhash.Hash][]chan struct{})

	for {

		select {
		case req := <-n.watchRequests:
			// If we've already seen this transaction, then
			// immediately dispatch the request. Otherwise, append
			// to the list of clients who are watching for the
			// broadcast of this transaction.
			if _, ok := seenTxns[req.txid]; ok {
				close(req.eventChan)
			} else {
				clients[req.txid] = append(clients[req.txid], req.eventChan)
			}
		case txid := <-n.seenTxns:
			// Add this txid to our set of "seen" transactions. So
			// we're able to dispatch any notifications for this
			// txid which arrive *after* it's seen within the
			// network.
			seenTxns[txid] = struct{}{}

			// If there isn't a registered notification for this
			// transaction then ignore it.
			txClients, ok := clients[txid]
			if !ok {
				continue
			}

			// Otherwise, dispatch the notification to all clients,
			// cleaning up the now un-needed state.
			for _, client := range txClients {
				close(client)
			}
			delete(clients, txid)
		}
	}
}

// OnTxAccepted is a callback to be called each time a new transaction has been
// broadcast on the network.
func (n *networkHarness) OnTxAccepted(hash *chainhash.Hash, amt btcutil.Amount) {
	go func() {
		n.seenTxns <- *hash
	}()
}

// WaitForTxBroadcast blocks until the target txid is seen on the network. If
// the transaction isn't seen within the network before the passed timeout,
// then an error is returned.
// TODO(roasbeef): add another method which creates queue of all seen transactions
func (n *networkHarness) WaitForTxBroadcast(ctx context.Context, txid chainhash.Hash) error {
	eventChan := make(chan struct{})

	n.watchRequests <- &watchRequest{txid, eventChan}

	select {
	case <-eventChan:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("tx not seen before context timeout")
	}
}

// OpenChannel attempts to open a channel between srcNode and destNode with the
// passed channel funding parameters. If the passed context has a timeout, then
// if the timeout is reached before the channel pending notification is
// received, an error is returned.
func (n *networkHarness) OpenChannel(ctx context.Context,
	srcNode, destNode *lightningNode, amt btcutil.Amount,
	pushAmt btcutil.Amount, numConfs uint32) (lnrpc.Lightning_OpenChannelClient, error) {

	openReq := &lnrpc.OpenChannelRequest{
		NodePubkey:         destNode.PubKey[:],
		LocalFundingAmount: int64(amt),
		PushSat:            int64(pushAmt),
		NumConfs:           numConfs,
	}

	respStream, err := srcNode.OpenChannel(ctx, openReq)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel between "+
			"alice and bob: %v", err)
	}

	chanOpen := make(chan struct{})
	errChan := make(chan error)
	go func() {
		// Consume the "channel pending" update. This waits until the node
		// notifies us that the final message in the channel funding workflow
		// has been sent to the remote node.
		resp, err := respStream.Recv()
		if err != nil {
			errChan <- err
			return
		}
		if _, ok := resp.Update.(*lnrpc.OpenStatusUpdate_ChanPending); !ok {
			errChan <- fmt.Errorf("expected channel pending update, "+
				"instead got %v", resp)
			return
		}

		close(chanOpen)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before chan pending "+
			"update sent: %v", err)
	case err := <-errChan:
		return nil, err
	case <-chanOpen:
		return respStream, nil
	}
}

// OpenPendingChannel attempts to open a channel between srcNode and destNode with the
// passed channel funding parameters. If the passed context has a timeout, then
// if the timeout is reached before the channel pending notification is
// received, an error is returned.
func (n *networkHarness) OpenPendingChannel(ctx context.Context,
	srcNode, destNode *lightningNode, amt btcutil.Amount,
	pushAmt btcutil.Amount, numConfs uint32) (*lnrpc.PendingUpdate, error) {

	openReq := &lnrpc.OpenChannelRequest{
		NodePubkey:         destNode.PubKey[:],
		LocalFundingAmount: int64(amt),
		PushSat:            int64(pushAmt),
		NumConfs:           numConfs,
	}

	respStream, err := srcNode.OpenChannel(ctx, openReq)
	if err != nil {
		return nil, fmt.Errorf("unable to open channel between "+
			"alice and bob: %v", err)
	}

	chanPending := make(chan *lnrpc.PendingUpdate)
	errChan := make(chan error)
	go func() {
		// Consume the "channel pending" update. This waits until the node
		// notifies us that the final message in the channel funding workflow
		// has been sent to the remote node.
		resp, err := respStream.Recv()
		if err != nil {
			errChan <- err
			return
		}
		pendingResp, ok := resp.Update.(*lnrpc.OpenStatusUpdate_ChanPending)
		if !ok {
			errChan <- fmt.Errorf("expected channel pending update, "+
				"instead got %v", resp)
			return
		}

		chanPending <- pendingResp.ChanPending
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before chan pending " +
			"update sent")
	case err := <-errChan:
		return nil, err
	case pendingChan := <-chanPending:
		return pendingChan, nil
	}
}

// WaitForChannelOpen waits for a notification that a channel is open by
// consuming a message from the past open channel stream. If the passed context
// has a timeout, then if the timeout is reached before the channel has been
// opened, then an error is returned.
func (n *networkHarness) WaitForChannelOpen(ctx context.Context,
	openChanStream lnrpc.Lightning_OpenChannelClient) (*lnrpc.ChannelPoint, error) {

	errChan := make(chan error)
	respChan := make(chan *lnrpc.ChannelPoint)
	go func() {
		resp, err := openChanStream.Recv()
		if err != nil {
			errChan <- fmt.Errorf("unable to read rpc resp: %v", err)
			return
		}
		fundingResp, ok := resp.Update.(*lnrpc.OpenStatusUpdate_ChanOpen)
		if !ok {
			errChan <- fmt.Errorf("expected channel open update, "+
				"instead got %v", resp)
			return
		}

		respChan <- fundingResp.ChanOpen.ChannelPoint
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached while waiting for " +
			"channel open")
	case err := <-errChan:
		return nil, err
	case chanPoint := <-respChan:
		return chanPoint, nil
	}
}

// CloseChannel close channel attempts to close the channel indicated by the
// passed channel point, initiated by the passed lnNode. If the passed context
// has a timeout, then if the timeout is reached before the channel close is
// pending, then an error is returned.
func (n *networkHarness) CloseChannel(ctx context.Context,
	lnNode *lightningNode, cp *lnrpc.ChannelPoint,
	force bool) (lnrpc.Lightning_CloseChannelClient, *chainhash.Hash, error) {

	closeReq := &lnrpc.CloseChannelRequest{
		ChannelPoint: cp,
		Force:        force,
	}
	closeRespStream, err := lnNode.CloseChannel(ctx, closeReq)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to close channel: %v", err)
	}

	errChan := make(chan error)
	fin := make(chan *chainhash.Hash)
	go func() {
		// Consume the "channel close" update in order to wait for the closing
		// transaction to be broadcast, then wait for the closing tx to be seen
		// within the network.
		closeResp, err := closeRespStream.Recv()
		if err != nil {
			errChan <- err
			return
		}
		pendingClose, ok := closeResp.Update.(*lnrpc.CloseStatusUpdate_ClosePending)
		if !ok {
			errChan <- fmt.Errorf("expected channel close update, "+
				"instead got %v", pendingClose)
			return
		}

		closeTxid, err := chainhash.NewHash(pendingClose.ClosePending.Txid)
		if err != nil {
			errChan <- err
			return
		}
		if err := n.WaitForTxBroadcast(ctx, *closeTxid); err != nil {
			errChan <- err
			return
		}
		fin <- closeTxid
	}()

	// Wait until either the deadline for the context expires, an error
	// occurs, or the channel close update is received.
	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("timeout reached before channel close " +
			"initiated")
	case err := <-errChan:
		return nil, nil, err
	case closeTxid := <-fin:
		return closeRespStream, closeTxid, nil
	}
}

// WaitForChannelClose waits for a notification from the passed channel close
// stream that the node has deemed the channel has been fully closed. If the
// passed context has a timeout, then if the timeout is reached before the
// notification is received then an error is returned.
func (n *networkHarness) WaitForChannelClose(ctx context.Context,
	closeChanStream lnrpc.Lightning_CloseChannelClient) (*chainhash.Hash, error) {

	errChan := make(chan error)
	updateChan := make(chan *lnrpc.CloseStatusUpdate_ChanClose)
	go func() {
		closeResp, err := closeChanStream.Recv()
		if err != nil {
			errChan <- err
			return
		}

		closeFin, ok := closeResp.Update.(*lnrpc.CloseStatusUpdate_ChanClose)
		if !ok {
			errChan <- fmt.Errorf("expected channel close update, "+
				"instead got %v", closeFin)
			return
		}

		updateChan <- closeFin
	}()

	// Wait until either the deadline for the context expires, an error
	// occurs, or the channel close update is received.
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout reached before update sent")
	case err := <-errChan:
		return nil, err
	case update := <-updateChan:
		return chainhash.NewHash(update.ChanClose.ClosingTxid)
	}
}

// AssertChannelExists asserts that an active channel identified by
// channelPoint is known to exist from the point-of-view of node..
func (n *networkHarness) AssertChannelExists(ctx context.Context,
	node *lightningNode, chanPoint *wire.OutPoint) error {

	req := &lnrpc.ListChannelsRequest{}
	resp, err := node.ListChannels(ctx, req)
	if err != nil {
		return fmt.Errorf("unable fetch node's channels: %v", err)
	}

	for _, channel := range resp.Channels {
		if channel.ChannelPoint == chanPoint.String() {
			return nil
		}
	}

	return fmt.Errorf("channel not found")
}

// DumpLogs reads the current logs generated by the passed node, and returns
// the logs as a single string. This function is useful for examining the logs
// of a particular node in the case of a test failure.
// Logs from lightning node being generated with delay - you should
// add time.Sleep() in order to get all logs.
func (n *networkHarness) DumpLogs(node *lightningNode) (string, error) {
	logFile := fmt.Sprintf("%v/simnet/lnd.log", node.cfg.LogDir)

	buf, err := ioutil.ReadFile(logFile)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

// SendCoins attempts to send amt satoshis from the internal mining node to the
// targeted lightning node.
func (n *networkHarness) SendCoins(ctx context.Context, amt btcutil.Amount,
	target *lightningNode) error {

	balReq := &lnrpc.WalletBalanceRequest{}
	initialBalance, err := target.WalletBalance(ctx, balReq)
	if err != nil {
		return err
	}

	// First, obtain an address from the target lightning node, preferring
	// to receive a p2wkh address s.t the output can immediately be used as
	// an input to a funding transaction.
	addrReq := &lnrpc.NewAddressRequest{
		Type: lnrpc.NewAddressRequest_WITNESS_PUBKEY_HASH,
	}
	resp, err := target.NewAddress(ctx, addrReq)
	if err != nil {
		return err
	}
	addr, err := btcutil.DecodeAddress(resp.Address, n.netParams)
	if err != nil {
		return err
	}
	addrScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}

	// Generate a transaction which creates an output to the target
	// pkScript of the desired amount.
	output := &wire.TxOut{
		PkScript: addrScript,
		Value:    int64(amt),
	}
	if _, err := n.Miner.SendOutputs([]*wire.TxOut{output}, 30); err != nil {
		return err
	}

	// Finally, generate 6 new blocks to ensure the output gains a
	// sufficient number of confirmations.
	if _, err := n.Miner.Node.Generate(6); err != nil {
		return err
	}

	// Pause until the nodes current wallet balances reflects the amount
	// sent to it above.
	// TODO(roasbeef): factor out into helper func
	for {
		select {
		case <-time.Tick(time.Millisecond * 50):
			currentBal, err := target.WalletBalance(ctx, balReq)
			if err != nil {
				return err
			}

			if currentBal.Balance == initialBalance.Balance+amt.ToBTC() {
				return nil
			}
		case <-time.After(time.Second * 30):
			return fmt.Errorf("balances not synced after deadline")
		}
	}
}

// connectionBridge is an integration helper which is used to connect the
// Alice and Bob to it and have the ability to watch the messages that are
// flying around between them.
//
// NOTE: Now  bridge can't be used because of our inability to retrieve private
// keys of Alice and Bob dynamically in integration tests. But this struct is
// done in such a way that it might be used in unit tests too.
type connectionBridge struct {
	// alice and bob private keys are needed because of 'brontide'
	// encryption connection, without it we can't pretend to be Alice for
	// Bob, and Bob for Alice.
	alicePrivKey, bobPrivKey *btcec.PrivateKey

	aliceListener, bobListener *brontide.Listener
	aliceConn, bobConn         net.Conn

	// handler the special object which corresponds the handler interface
	// and returns the handler function which will be used to handle the
	// messages which are going through the bridge.
	handler bridgeHandler

	// capture is an atomic variable which is used to indicate the need
	// for capturing the message and pass them to handler.
	capture int32

	stopped int32
	started int32
	quit    chan struct{}
	errChan chan error
	wg      sync.WaitGroup
}

// newConnectionBridge creates new instance of bridge.
func newConnectionBridge(alicePrivKey, bobPrivKey *btcec.PrivateKey,
	handler bridgeHandler) (*connectionBridge, error) {

	// addresses to which bob and alice should connect.
	addrForBob := "127.0.0.1:44444"
	addrForAlice := "127.0.0.1:55555"

	bobListener, err := brontide.NewListener(alicePrivKey, addrForBob)
	if err != nil {
		return nil, err
	}

	aliceListener, err := brontide.NewListener(bobPrivKey, addrForAlice)
	if err != nil {
		return nil, err
	}

	return &connectionBridge{
		alicePrivKey: alicePrivKey,
		bobPrivKey:   bobPrivKey,

		aliceListener: aliceListener,
		bobListener:   bobListener,

		errChan: make(chan error, 10),
		quit:    make(chan struct{}),

		handler: handler,
	}, nil
}

// endpointForAlice returns the net address/endpoint for Alice need to connect
// so her messages might be captured.
func (b *connectionBridge) endpointForAlice() *lnwire.NetAddress {
	return &lnwire.NetAddress{
		IdentityKey: b.bobPrivKey.PubKey(),
		Address:     b.aliceListener.Addr().(*net.TCPAddr),
	}
}

// endpointForBob returns the net address/endpoint for Bob need to connect
// so her messages might be captured.
func (b *connectionBridge) endpointForBob() *lnwire.NetAddress {
	return &lnwire.NetAddress{
		IdentityKey: b.alicePrivKey.PubKey(),
		Address:     b.bobListener.Addr().(*net.TCPAddr),
	}
}

// waitForShutdown waits service to be shut down and return internal error if
// it was sent to us from one of the internal goroutines.
func (b *connectionBridge) waitForShutdown() error {
	err := <-b.errChan

	// If service was shut down during some internal error than it wasn't
	// stopped, so we should do it.
	if err := b.stop(); err != nil {
		return err
	}

	b.wg.Wait()
	return err
}

// stop function notifies the subsystem about service shut down.
func (b *connectionBridge) stop() error {
	if !atomic.CompareAndSwapInt32(&b.stopped, 0, 1) {
		return nil
	}

	b.stopCapturing()

	close(b.quit)
	close(b.errChan)

	if b.aliceConn != nil {
		if err := b.aliceConn.Close(); err != nil {
			return err
		}
	}

	if b.bobConn != nil {
		if err := b.bobConn.Close(); err != nil {
			return err
		}
	}

	if err := b.bobListener.Close(); err != nil {
		return err
	}

	if err := b.aliceListener.Close(); err != nil {
		return err
	}

	return nil
}

// start function executes the retranslation goroutine.
func (b *connectionBridge) start() {
	if !atomic.CompareAndSwapInt32(&b.started, 0, 1) {
		return
	}

	b.wg.Add(1)
	go b.startRetranslation()
}

// startRetranslation initialize listeners and wait for Alice and Bob connect to
// their endpoints, after that the retransmission will be executed without
// intercepting the messages.
//
// NOTE: Should be executed as goroutine.
func (b *connectionBridge) startRetranslation() {
	defer b.wg.Done()

	// Run initialization of connections in standalone goroutines as far as
	// we don't want to force the user/programmer keep specific order of
	// dial connections in tests.

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := b.bobListener.Accept()
		select {
		case <-b.quit:
		default:
			if err != nil {
				b.errChan <- err
			} else {
				b.bobConn = conn
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := b.aliceListener.Accept()
		select {
		case <-b.quit:
		default:
			if err != nil {
				b.errChan <- err
			} else {
				b.aliceConn = conn
			}
		}
	}()

	// Wait for connections to be initialized, but also checks service
	// wasn't shut down during connection initialization.
	wg.Wait()
	select {
	case <-b.quit:
		return
	default:
	}

	handler := b.handler.Handler()

	// Run two standalone goroutines in order re-translate message in non
	// blocking manner.
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		for {
			err := b.retransmit(b.aliceConn, b.bobConn, handler)
			select {
			case <-b.quit:
				return
			default:
				if err != nil {
					b.errChan <- err
					return
				}
			}
		}
	}()

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		for {
			err := b.retransmit(b.bobConn, b.aliceConn, handler)
			select {
			case <-b.quit:
				return
			default:
				if err != nil {
					b.errChan <- err
					return
				}
			}
		}
	}()
}

// startCapturing start intercepting messages that are flying around between
// nodes and pass the to the handler.
func (b *connectionBridge) startCapturing() {
	if !atomic.CompareAndSwapInt32(&b.capture, 0, 1) {
		return
	}

	b.handler.Init(b)
}

// stopCapturing stop intercepting messages that are flying around between
// nodes.
func (b *connectionBridge) stopCapturing() {
	if !atomic.CompareAndSwapInt32(&b.capture, 1, 0) {
		return
	}

	b.handler.TearDown()
}

// retransmit function reads messages from reader (it might be first tcp
// connection), pass it to the handler function and retransmit message to
// writer (it might be second tcp connection).
func (b *connectionBridge) retransmit(r io.Reader, w io.Writer,
	f func(lnwire.Message) (bool, error)) error {

	n, msg, _, err := lnwire.ReadMessage(r, 0, wire.SimNet)
	if err != nil {
		return err
	} else if n == 0 {
		return nil
	}

	if atomic.LoadInt32(&b.capture) == 1 {
		if skip, err := f(msg); err != nil {
			return err
		} else if skip {
			return nil
		}
	}

	_, err = lnwire.WriteMessage(w, msg, 0, wire.SimNet)
	if err != nil {
		return err
	}

	return nil
}

// bridgeHandler is an interface which represent the bridge message handler.
type bridgeHandler interface {
	// Init used to initialize the handler before the message capturing
	// is started.
	Init(*connectionBridge)

	// TearDown used to do all necessary work before message capturing is
	// stopped. Even if intercepting will be stopped without handling all
	// intercepted messages they should be safely sent to other side without
	// loss.
	TearDown()

	// Handler returns the function which will be used as handler for
	// messages that flying around between nodes. This function should
	// return the error and bool - should this message be sent to another
	// side.
	// NOTE: Be aware that message might be sent to handler even if
	// capturing was stopped because of async behaviour of goroutines.
	Handler() func(msg lnwire.Message) (bool, error)
}

// stopHandler is handler which is used when intercepted messages need to be
// read one by one
type stopHandler struct {
	next    chan bool
	msgChan chan lnwire.Message
	bridge  *connectionBridge
}

// newStopHandler returns new instance of stopHandler.
func newStopHandler() *stopHandler {
	return &stopHandler{
		msgChan: make(chan lnwire.Message),
	}
}

// Init The message will not be sent to other party until it will be
// read.
// NOTE: Part of the bridgeHandler interface.
func (h *stopHandler) Init(bridge *connectionBridge) {
	h.bridge = bridge
	h.next = make(chan bool)
}

// TearDown function close the 'next' channel thereby gives the ability for
// all messages that were waiting to be read to be sent to remote side.
// NOTE: Part of the bridgeHandler interface.
func (h *stopHandler) TearDown() {
	close(h.next)
}

// Handler stops retransmission of message until message is read by
// getCapturedMessage function.
// NOTE: Part of the bridgeHandler interface.
func (h *stopHandler) Handler() func(msg lnwire.Message) (bool, error) {
	return func(msg lnwire.Message) (bool, error) {
		_, ok := <-h.next
		if !ok {
			return false, nil
		}

		h.msgChan <- msg
		return false, nil
	}
}

// getCapturedMessage waits for messages to be sent over bridge and returns
// it after it was intercepted.
func (h *stopHandler) getCapturedMessage() (lnwire.Message, error) {
	if atomic.LoadInt32(&h.bridge.capture) == 0 {
		return nil, errors.New("interception was stopped")
	}

	select {
	case h.next <- true:
	case <-h.bridge.quit:
		return nil, errors.New("bridge was closed")
	}

	select {
	case msg := <-h.msgChan:
		return msg, nil
	case <-h.bridge.quit:
		return nil, errors.New("bridge was closed")
	}
}

// dynamicHandler might be used inside the test on order to not create the
// handler globally. It is needed if handler will be used only on test level.
type dynamicHandler struct {
	init     func(bridge *connectionBridge)
	tearDown func()
	handler  func(msg lnwire.Message) (bool, error)
	mutex    sync.Mutex
}

// NOTE: Part of the bridgeHandler interface.
func (h *dynamicHandler) Init(bridge *connectionBridge) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.init != nil {
		h.init(bridge)
	}
}

// NOTE: Part of the bridgeHandler interface.
func (h *dynamicHandler) TearDown() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.tearDown != nil {
		h.tearDown()
	}
}

// NOTE: Part of the bridgeHandler interface.
func (h *dynamicHandler) Handler() func(msg lnwire.Message) (bool, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.handler != nil {
		return h.handler
	}

	return func(msg lnwire.Message) (bool, error) {
		return false, nil
	}
}

// SetInit set the init function in safe manner.
func (h *dynamicHandler) SetInit(f func(bridge *connectionBridge)) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.init = f
}

// SetHandler set the handler function in safe manner.
func (h *dynamicHandler) SetHandler(f func(msg lnwire.Message) (bool, error)) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.handler = f
}

// SetTearDown set the teardown function in safe manner.
func (h *dynamicHandler) SetTearDown(f func()) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.tearDown = f
}
