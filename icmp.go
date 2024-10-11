package traceroute

import (
	"bytes"
	"encoding/binary"
)

type icmp struct {
	ICMPType uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	SEQ      uint16
}

func newEchoRequest(icmpType, code byte) *icmp {
	return &icmp{
		ICMPType: icmpType,
		Code:     code,
		ID:       0x42,
		SEQ:      0x1337,
	}
}

func (h *icmp) Bytes() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, h)
	data := b.Bytes()
	packetcsum := data[2:4]
	calcChecksum(data, &packetcsum)
	return data
}

// Function for calculating and installation csum for packet
func calcChecksum(packet []byte, pcsum *[]byte) {
	calcsum := csum(packet)
	(*pcsum)[0] = uint8((calcsum >> 8) & 0xFF)
	(*pcsum)[1] = uint8(calcsum & 0xFF)
}

func csum(buf []byte) uint16 {
	sum := uint32(0)
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}
