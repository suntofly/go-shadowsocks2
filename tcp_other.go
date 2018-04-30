// +build !linux

package main

import ssnet "github.com/shadowsocks/go-shadowsocks2/net"

func redirLocal(addr, server string, shadow func(ssnet.DuplexConn) ssnet.DuplexConn) {
	logf("TCP redirect not supported")
}

func redir6Local(addr, server string, shadow func(ssnet.DuplexConn) ssnet.DuplexConn) {
	logf("TCP6 redirect not supported")
}
