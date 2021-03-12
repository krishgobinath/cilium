package wireguard

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	listenPort       = 51871
	wgIfaceName      = "wg0"                          // TODO make config param
	PubKeyAnnotation = "io.cilium.network.wg-pub-key" // TODO use consts from other pkg
)

type Agent struct {
	lock.RWMutex

	wgClient *wgctrl.Client
	privKey  wgtypes.Key

	wireguardV4CIDR *net.IPNet
	wireguardIPv4   net.IP

	restoredPubKeys map[string]struct{}
	finishedRestore bool

	listenPort int

	pubKeyByNodeName map[string]string // nodeName => pubKey
}

func NewAgent(privKey string, wgV4Net *net.IPNet) (*Agent, error) {
	key, err := loadOrGeneratePrivKey(privKey)
	if err != nil {
		return nil, err
	}

	node.SetWireguardPubKey(key.PublicKey().String())

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	return &Agent{
		wgClient: wgClient,
		privKey:  key,

		wireguardIPv4:   nil, // set by node manager
		wireguardV4CIDR: wgV4Net,

		listenPort: listenPort, // TODO make configurable

		pubKeyByNodeName: map[string]string{},
		restoredPubKeys:  map[string]struct{}{},
	}, nil
}

// TODO call this
func (a *Agent) Close() error {
	return a.wgClient.Close()
}

func (a *Agent) Init() error {
	// TODO check if it exists
	if node.GetWireguardIPv4() == nil {
		return fmt.Errorf("Failed to retrieve wireguard IPv4")
	}

	a.wireguardIPv4 = node.GetWireguardIPv4()

	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: wgIfaceName}}
	err := netlink.LinkAdd(link)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}

	ip := &net.IPNet{
		IP:   a.wireguardIPv4,
		Mask: a.wireguardV4CIDR.Mask,
	}

	// Removes stale IP addresses from wg device
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if !cidr.NewCIDR(addr.IPNet).Equal(cidr.NewCIDR(ip)) {
			if err := netlink.AddrDel(link, &addr); err != nil {
				return fmt.Errorf("failed to remove stale wg ip: %w", err)
			}
		}
	}

	err = netlink.AddrAdd(link, &netlink.Addr{IPNet: ip})
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}

	cfg := &wgtypes.Config{
		PrivateKey:   &a.privKey,
		ListenPort:   &a.listenPort,
		ReplacePeers: false,
	}
	if err := a.wgClient.ConfigureDevice(wgIfaceName, *cfg); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	dev, err := a.wgClient.Device(wgIfaceName)
	if err != nil {
		return err
	}
	for _, peer := range dev.Peers {
		a.restoredPubKeys[peer.PublicKey.String()] = struct{}{}
	}

	return nil
}

func (a *Agent) RestoreFinished() error {
	a.Lock()
	defer a.Unlock()

	// Delete obsolete peers
	for _, pubKeyHex := range a.pubKeyByNodeName {
		delete(a.restoredPubKeys, pubKeyHex)
	}
	for pubKeyHex := range a.restoredPubKeys {
		if err := a.deletePeerByPubKey(pubKeyHex); err != nil {
			return err
		}
	}

	a.finishedRestore = true

	return nil
}

func (a *Agent) UpdatePeer(nodeName string, wgIPv4, nodeIPv4 net.IP, pubKeyHex string, podCIDRv4 *net.IPNet, isLocal bool) error {
	a.Lock()
	defer a.Unlock()

	if isLocal {
		return nil
	}

	if !a.finishedRestore {
		a.restoredPubKeys[pubKeyHex] = struct{}{}
	}

	// Handle pubKey change
	if a.finishedRestore {
		if prevPubKeyHex, found := a.pubKeyByNodeName[nodeName]; found && prevPubKeyHex != pubKeyHex {
			// pubKeys differ, so delete old peer
			if err := a.deletePeerByPubKey(prevPubKeyHex); err != nil {
				return err
			}
			delete(a.pubKeyByNodeName, nodeName)
		}
	}

	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	var peerIPNet net.IPNet
	peerIPNet.IP = wgIPv4
	peerIPNet.Mask = net.IPv4Mask(255, 255, 255, 255)

	epAddr, err := net.ResolveUDPAddr("udp", nodeIPv4.String()+":"+strconv.Itoa(listenPort))
	if err != nil {
		return err
	}

	allowedIPs := []net.IPNet{peerIPNet}
	if podCIDRv4 != nil {
		allowedIPs = append(allowedIPs, *podCIDRv4)
	}

	peerConfig := wgtypes.PeerConfig{
		Endpoint:          epAddr,
		PublicKey:         pubKey,
		AllowedIPs:        allowedIPs,
		ReplaceAllowedIPs: true,
	}
	cfg := &wgtypes.Config{ReplacePeers: false, Peers: []wgtypes.PeerConfig{peerConfig}}
	if err := a.wgClient.ConfigureDevice(wgIfaceName, *cfg); err != nil {
		return err
	}

	a.pubKeyByNodeName[nodeName] = pubKeyHex

	return nil
}

func (a *Agent) DeletePeer(nodeName string) error {
	a.Lock()
	defer a.Unlock()

	pubKeyHex, found := a.pubKeyByNodeName[nodeName]
	if !found {
		return fmt.Errorf("cannot find pubkey for %s node", nodeName)
	}

	if err := a.deletePeerByPubKey(pubKeyHex); err != nil {
		return err
	}

	delete(a.pubKeyByNodeName, nodeName)

	if !a.finishedRestore {
		delete(a.restoredPubKeys, pubKeyHex)
	}

	return nil
}

func (a *Agent) deletePeerByPubKey(pubKeyHex string) error {
	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	cfg := &wgtypes.Config{Peers: []wgtypes.PeerConfig{peerCfg}}
	if err := a.wgClient.ConfigureDevice(wgIfaceName, *cfg); err != nil {
		return err
	}

	return nil
}

func loadOrGeneratePrivKey(filePath string) (key wgtypes.Key, err error) {
	bytes, err := ioutil.ReadFile(filePath)
	if os.IsNotExist(err) {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to generate wg private key: %w", err)
		}

		err = ioutil.WriteFile(filePath, key[:], os.ModePerm) // TODO fix do not use 777 for priv key
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to save wg private key: %w", err)
		}

		return key, nil
	} else if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to load wg private key: %w", err)
	}

	return wgtypes.NewKey(bytes)
}
