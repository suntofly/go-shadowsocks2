package server

import (
	"net"
	"testing"
)

type constantDialer struct {
	*net.Dialer
	conn    net.Conn
	network string
	address string
}

func (cd *constantDialer) Dial(network, address string) (net.Conn, error) {
	cd.network = network
	cd.address = address
	localConn, remoteConn := net.Pipe()
	cd.conn = remoteConn
	return localConn, nil
}

func testSocksRoute(t *testing.T) {
	dialer := constantDialer{}
	localConn, remoteConn := net.Pipe()
	SocksRoute(remoteConn, dialer)
}
