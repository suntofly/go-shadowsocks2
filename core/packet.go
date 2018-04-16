package core

import (
	"net"
	"sync"
	"time"

	"github.com/riobard/go-shadowsocks2/socks"
)

func ListenPacket(network, address string, ciph PacketConnCipher) (net.PacketConn, error) {
	c, err := net.ListenPacket(network, address)
	return ciph.PacketConn(c), err
}

// copy from src to dst at target with read timeout
func TimedCopy(target net.Addr, dst, src net.PacketConn, timeout time.Duration, bufPool *sync.Pool, prependSrcAddr bool) error {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		if prependSrcAddr { // server -> client: prepend original packet source address
			srcAddr := socks.ParseAddr(raddr.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			if _, err = dst.WriteTo(buf[:len(srcAddr)+n], target); err != nil {
				return err
			}
		} else { // client -> user: strip original packet source address
			srcAddr := socks.SplitAddr(buf[:n])
			if _, err = dst.WriteTo(buf[len(srcAddr):n], target); err != nil {
				return err
			}
		}
	}
}
