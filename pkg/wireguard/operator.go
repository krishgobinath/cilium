package wireguard

import (
	"fmt"
	"net"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/addressing"

	"github.com/cilium/ipam/service/ipallocator"
	"k8s.io/client-go/util/retry"
)

type CiliumNodeUpdater interface {
	Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(node string) (*v2.CiliumNode, error)
}

type Operator struct {
	lock.RWMutex
	ipAlloc                   *ipallocator.Range
	restoring                 bool
	allocForNodesAfterRestore map[string]struct{}
	ciliumNodeUpdater         CiliumNodeUpdater
}

func NewOperator(subnetV4 *net.IPNet, ciliumNodeUpdater CiliumNodeUpdater) (*Operator, error) {
	alloc, err := ipallocator.NewCIDRRange(subnetV4)
	if err != nil {
		return nil, err
	}

	m := &Operator{
		ipAlloc:                   alloc,
		restoring:                 true,
		allocForNodesAfterRestore: make(map[string]struct{}),
		ciliumNodeUpdater:         ciliumNodeUpdater,
	}

	return m, nil
}

func (o *Operator) AddNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	return o.allocateIP(n, false)
}

func (o *Operator) UpdateNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	return o.allocateIP(n, true)
}

func (o *Operator) DeleteNode(n *v2.CiliumNode) {
	o.Lock()
	defer o.Unlock()

	if o.restoring {
		panic("INVALID STATE") // TODO log err
	}

	found := false
	var ip net.IP
	for _, addr := range n.Spec.Addresses {
		if addr.Type == addressing.NodeWireguardIP {
			ip = net.ParseIP(addr.IP)
			if ip.To4() != nil {
				found = true
				break
			}
		}
	}

	if found {
		if o.restoring {
			delete(o.allocForNodesAfterRestore, n.ObjectMeta.Name)
		}
		o.ipAlloc.Release(ip)
	}
}

func (o *Operator) Resync() error {
	o.Lock()
	defer o.Unlock()

	o.restoring = false
	for nodeName := range o.allocForNodesAfterRestore {
		ip, err := o.ipAlloc.AllocateNext()
		if err != nil {
			return fmt.Errorf("failed to allocate IP addr for node %s: %w", nodeName)
		}
		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			return err
		}
	}

	return nil
}

// allocateIP must be called with *Operator mutex being held.
func (o *Operator) allocateIP(n *v2.CiliumNode, isUpdate bool) error {
	found := false
	var ip net.IP
	for _, addr := range n.Spec.Addresses {
		if addr.Type == addressing.NodeWireguardIP {
			ip = net.ParseIP(addr.IP)
			if ip.To4() != nil {
				found = true
				break
			}
		}
	}

	if !found {
		if o.restoring {
			o.allocForNodesAfterRestore[n.ObjectMeta.Name] = struct{}{}
		} else {
			ip, err := o.ipAlloc.AllocateNext()
			if err != nil {
				return fmt.Errorf("failed to allocate IP addr for node %s: %w", n.ObjectMeta.Name)
			}

			if err := o.setCiliumNodeIP(n.ObjectMeta.Name, ip); err != nil {
				return err
			}
		}
	} else if !isUpdate {
		if err := o.ipAlloc.Allocate(ip); err != nil {
			return fmt.Errorf("failed to re-allocate IP addr %s for node %s: %w", ip, n.ObjectMeta.Name, err)
		}
	}

	return nil
}

func (o *Operator) setCiliumNodeIP(nodeName string, ip net.IP) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := o.ciliumNodeUpdater.Get(nodeName)
		if err != nil {
			return err
		}

		node.Spec.Addresses = append(node.Spec.Addresses, v2.NodeAddress{Type: addressing.NodeWireguardIP, IP: ip.String()})
		_, err = o.ciliumNodeUpdater.Update(nil, node)
		return err
	})
	return err
}
