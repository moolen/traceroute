package traceroute

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"syscall"
	"time"
)

type Hop struct {
	IP          net.IP
	TTL         int
	Names       []string
	ReceiveTime time.Duration
}

func TraceWithTTL(ctx context.Context, addr net.IP, maxTTL int) ([]*Hop, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	sock := os.NewFile(uintptr(fd), "")
	defer sock.Close()
	var hops []*Hop

	for i := 1; i <= maxTTL; i++ {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
			hop, err := measureHop(i, sock, addr)
			if err != nil {
				return nil, err
			}
			hops = append(hops, hop)
			if hop.IP.Equal(addr) {
				return hops, nil
			}
		}
	}
	return hops, nil
}

func measureHop(ttl int, sock *os.File, addr net.IP) (*Hop, error) {
	syscall.SetsockoptByte(int(sock.Fd()), syscall.IPPROTO_IP, syscall.IP_TTL, uint8(ttl))
	start := time.Now()
	pkt := newEchoRequest(0x8, 0x0).Bytes()
	sendPacket(int(sock.Fd()), syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte(addr.To4()),
	}, pkt)
	icmpResponse := make([]byte, 56)
	rb, err := sock.Read(icmpResponse)
	received := time.Since(start)
	if err != nil {
		return nil, err
	}
	if rb < 28 {
		return nil, fmt.Errorf("invalid icmp response: %#v", icmpResponse)
	}

	respondingAddr := net.IP([]byte(icmpResponse[12:16]))
	names, _ := net.LookupAddr(respondingAddr.String())

	switch icmpResponse[20] {
	// reply
	case 0x0:
		{
			if reflect.DeepEqual(icmpResponse[12:16], []byte(addr)) {
				return &Hop{
					IP:          respondingAddr,
					TTL:         ttl,
					Names:       names,
					ReceiveTime: received,
				}, nil
			}
		}
	// TTL exceeded
	case 0x0B:
		{
			if reflect.DeepEqual(icmpResponse[48:], pkt[:]) {
				return &Hop{
					IP:          respondingAddr,
					TTL:         ttl,
					Names:       names,
					ReceiveTime: received,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("unexpected icmp response: %v", icmpResponse)
}

func sendPacket(fd int, destAddr syscall.SockaddrInet4, icmppacket []byte) error {
	if err := syscall.Sendto(fd, icmppacket, 0, &destAddr); err != nil {
		return fmt.Errorf("unable to send icmp packet: %w", err)
	}
	return nil
}
