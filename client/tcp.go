package client

import (
	"net"
	"time"

	"github.com/riobard/go-shadowsocks2/core"
	"github.com/riobard/go-shadowsocks2/log"
	"github.com/riobard/go-shadowsocks2/socks"
)

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(3 * time.Minute)
	}
}

// Create a SOCKS server listening on addr and proxy to server.
func SocksLocal(addr string, d Dialer) {
	log.VLogf("SOCKS proxy %s", addr)
	TCPLocal(addr, d, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// Create a TCP tunnel from addr to target via server.
func TCPTun(addr, target string, d Dialer) {
	tgt := socks.ParseAddr(target)
	if tgt == nil {
		log.VLogf("invalid target address %q", target)
		return
	}
	log.VLogf("TCP tunnel %s <-> %s", addr, target)
	TCPLocal(addr, d, func(net.Conn) (socks.Addr, error) { return tgt, nil })
}

// Listen on addr and proxy to server to reach target from getAddr.
func TCPLocal(addr string, d Dialer, getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.VLogf("failed to listen on %s: %v", addr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			log.VLogf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			tcpKeepAlive(c)

			tgt, err := getAddr(c)
			if err != nil {
				log.VLogf("failed to get target address: %v", err)
				return
			}

			rc, err := d.Dial("tcp", tgt.String())
			if err != nil {
				log.VLogf("failed to connect: %v", err)
				return
			}
			defer rc.Close()
			tcpKeepAlive(rc)

			log.VLogf("proxy %s <--[%s]--> %s", c.RemoteAddr(), rc.RemoteAddr(), tgt)
			if err = core.Relay(rc, c); err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				log.VLogf("relay error: %v", err)
			}
		}()
	}
}
