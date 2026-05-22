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
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return nil
	}

	key := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
	value := uint32(1)
	return m.objs.BlockList.Update(key, value, 0)
}

func (m *XDPManager) Close() {
	if m.link != nil {
		m.link.Close()
	}
	m.objs.Close()
}
