package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip xdp c/xdp_fw.c -- -I./c/include

import (
	"log"
	"net"

	"github.com/cilium/ebpf/link"
)

type XDPManager struct {
	objs xdpObjects
	link link.Link
}

func NewXDPManager() *XDPManager {
	return &XDPManager{}
}

func (m *XDPManager) Load(ifaceName string) error {
	// Load pre-compiled programs and maps into the kernel.
	if err := loadXdpObjects(&m.objs, nil); err != nil {
		return err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	m.link = l
	log.Printf("XDP program attached to %s", ifaceName)
	return nil
}

func (m *XDPManager) BlockIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	var key [16]byte
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4-mapped IPv6
		copy(key[10:12], []byte{0xff, 0xff})
		copy(key[12:16], ip4)
	} else {
		copy(key[:], ip.To16())
	}

	value := uint32(1)
	return m.objs.BlockList.Update(key, value, 0)
}

func (m *XDPManager) Close() {
	if m.link != nil {
		m.link.Close()
	}
	m.objs.Close()
}
