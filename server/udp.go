package server

import (
	"net"
	"sync"
	"time"

	"github.com/riobard/go-shadowsocks2/core"
	"github.com/riobard/go-shadowsocks2/log"
	"github.com/riobard/go-shadowsocks2/socks"
)

// UDPRemote listens on addr for encrypted packets and basically do UDP NAT.
func UDPRemote(addr string, shadow func(net.PacketConn) net.PacketConn, timeout time.Duration, bufPool *sync.Pool) {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.VLogf("UDP remote listen error: %v", err)
		return
	}
	defer c.Close()
	c = shadow(c)

	m := make(map[string]chan []byte)
	var lock sync.Mutex

	log.VLogf("listening UDP on %s", addr)
	for {
		buf := bufPool.Get().([]byte)
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			log.VLogf("UDP remote read error: %v", err)
			continue
		}

		lock.Lock()
		k := raddr.String()
		ch := m[k]
		if ch == nil {
			pc, err := net.ListenPacket("udp", "")
			if err != nil {
				log.VLogf("failed to create UDP socket: %v", err)
				goto Unlock
			}
			ch = make(chan []byte, 1) // must use buffered chan
			m[k] = ch

			go func() { // receive from udpLocal and send to target
				var tgtUDPAddr *net.UDPAddr
				var err error

				for buf := range ch {
					tgtAddr := socks.SplitAddr(buf)
					if tgtAddr == nil {
						log.VLogf("failed to split target address from packet: %q", buf)
						goto End
					}
					tgtUDPAddr, err = net.ResolveUDPAddr("udp", tgtAddr.String())
					if err != nil {
						log.VLogf("failed to resolve target UDP address: %v", err)
						goto End
					}
					pc.SetReadDeadline(time.Now().Add(timeout))
					if _, err = pc.WriteTo(buf[len(tgtAddr):], tgtUDPAddr); err != nil {
						log.VLogf("UDP remote write error: %v", err)
						goto End
					}
				End:
					bufPool.Put(buf[:cap(buf)])
				}
			}()

			go func() { // receive from udpLocal and send to client
				if err := core.TimedCopy(raddr, c, pc, timeout, bufPool, true); err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						// ignore i/o timeout
					} else {
						log.VLogf("timedCopy error: %v", err)
					}
				}
				pc.Close()
				lock.Lock()
				if ch := m[k]; ch != nil {
					close(ch)
				}
				delete(m, k)
				lock.Unlock()
			}()
		}
	Unlock:
		lock.Unlock()

		select {
		case ch <- buf[:n]: // sent
		default: // drop
			bufPool.Put(buf)
		}
	}
}
