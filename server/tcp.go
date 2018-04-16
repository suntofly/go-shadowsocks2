package server

import (
	"bytes"
	"fmt"
	"io"
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

type readConn struct {
	net.Conn
	io.Reader
}

func (c readConn) Read(b []byte) (int, error) {
	return c.Reader.Read(b)
}

func findCipher(shadowConn net.Conn, unshadowList ...func(net.Conn) net.Conn) (net.Conn, error) {
	if len(unshadowList) == 1 {
		return unshadowList[0](shadowConn), nil
	}
	// buffer saves the bytes read from shadowConn, in order to allow for replays.
	var buffer bytes.Buffer
	// Try each cipher until we find one that authenticates successfully.
	// This assumes that all ciphers are AEAD.
	for i, unshadow := range unshadowList {
		log.VLogf("Trying cipher %v", i)
		// tmpReader reuses the bytes read so far, falling back to shadowConn if it needs more
		// bytes. All bytes read from shadowConn are saved in buffer.
		tmpReader := io.MultiReader(bytes.NewReader(buffer.Bytes()), io.TeeReader(shadowConn, &buffer))
		// Override the Reader of shadowConn so we can reset it for each cipher test.
		tmpConn := unshadow(readConn{Conn: shadowConn, Reader: tmpReader})
		// Read should read just enough data to authenticate the payload size.
		_, err := tmpConn.Read(make([]byte, 0))
		if err != nil {
			log.VLogf("Failed cipher %v", i)
			continue
		}
		log.VLogf("Selected cipher %v", i)
		// We don't need to replay the bytes anymore, but we don't want to drop those
		// read so far.
		clearReader := io.MultiReader(&buffer, shadowConn)
		return unshadow(readConn{Conn: shadowConn, Reader: clearReader}), nil
	}
	return nil, fmt.Errorf("could not find valid cipher")
}

// TCPRemote runs a Shadowsocks server listening on addr.
// It uses unShadow() to remove the Shadowsocks encryption layer.
func TCPRemote(addr string, unshadowList ...func(net.Conn) net.Conn) {
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
			defer shadowConn.Close()
			clearConn, err := findCipher(shadowConn, unshadowList...)
			if err != nil {
				log.VLogf(err.Error())
				return
			}
			err = SocksRoute(clearConn, tcpDial)
			if err != nil {
				log.VLogf(err.Error())
			}
		}()
	}
}
