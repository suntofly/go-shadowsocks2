package client

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/riobard/go-shadowsocks2/core"
	"github.com/riobard/go-shadowsocks2/log"
	"github.com/riobard/go-shadowsocks2/socks"
)

// Listen on laddr for UDP packets, encrypt and send to server to reach target.
func UDPLocal(laddr, server, target string, shadow func(net.PacketConn) net.PacketConn, timeout time.Duration, bufPool *sync.Pool) {
	srvAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		log.VLogf("UDP server address error: %v", err)
		return
	}

	tgt := socks.ParseAddr(target)
	if tgt == nil {
		err = fmt.Errorf("invalid target address: %q", target)
		log.VLogf("UDP target address error: %v", err)
		return
	}

	c, err := net.ListenPacket("udp", laddr)
	if err != nil {
		log.VLogf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()

	m := make(map[string]chan []byte)
	var lock sync.Mutex

	log.VLogf("UDP tunnel %s <-> %s <-> %s", laddr, server, target)
	for {
		buf := bufPool.Get().([]byte)
		copy(buf, tgt)
		n, raddr, err := c.ReadFrom(buf[len(tgt):])
		if err != nil {
			log.VLogf("UDP local read error: %v", err)
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
			pc = shadow(pc)
			ch = make(chan []byte, 1) // must use buffered chan
			m[k] = ch

			go func() { // recv from user and send to udpRemote
				for buf := range ch {
					pc.SetReadDeadline(time.Now().Add(timeout)) // extend read timeout
					if _, err := pc.WriteTo(buf, srvAddr); err != nil {
						log.VLogf("UDP local write error: %v", err)
					}
					bufPool.Put(buf[:cap(buf)])
				}
			}()

			go func() { // recv from udpRemote and send to user
				if err := core.TimedCopy(raddr, c, pc, timeout, bufPool, false); err != nil {
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
		case ch <- buf[:len(tgt)+n]: // send
		default: // drop
			bufPool.Put(buf)
		}
	}
}
