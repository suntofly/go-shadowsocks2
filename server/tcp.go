package server

import (
	"fmt"
	"net"
	"time"

	"github.com/riobard/go-shadowsocks2/core"
	"github.com/riobard/go-shadowsocks2/log"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(3 * time.Minute)
	}
}

// SocksRoute performs Shadowsocks Socks routing by reading
// the address header in the connection and relaying the
// traffic to the destination. It uses dial(address) to connect
// to the destination.
func SocksRoute(conn net.Conn, dial func(string) (net.Conn, error)) error {
	defer conn.Close()
	tcpKeepAlive(conn)

	tgt, err := socks.ReadAddr(conn)
	if err != nil {
		return fmt.Errorf("failed to get target address: %v", err)
	}

	rc, err := dial(tgt.String())
	if err != nil {
		return fmt.Errorf("failed to connect to target: %v", err)
	}
	defer rc.Close()
	tcpKeepAlive(rc)

	log.VLogf("proxy %s <-> %s", conn.RemoteAddr(), tgt)
	if err = core.Relay(conn, rc); err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return nil // ignore i/o timeout
		}
		return fmt.Errorf("relay error: %v", err)
	}
	return nil
}

// tcpDial dials the given address using TCP.
func tcpDial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

// TCPRemote runs a Shadowsocks server listening on addr.
// It uses unShadow() to remove the Shadowsocks encryption layer.
func TCPRemote(addr string, unShadow func(net.Conn) net.Conn) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.VLogf("failed to listen on %s: %v", addr, err)
		return
	}
	log.VLogf("listening TCP on %s", addr)
	for {
		shadowConn, err := listener.Accept()
		if err != nil {
			log.VLogf("failed to accept: %v", err)
			continue
		}
		go func() {
			clearConn := unShadow(shadowConn)
			err := SocksRoute(clearConn, tcpDial)
			if err != nil {
				log.VLogf(err.Error())
			}
		}()
	}
}
