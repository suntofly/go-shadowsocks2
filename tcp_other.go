// +build !linux

package main

import (
	"net"

	"github.com/shadowsocks/go-shadowsocks2/log"
)

func redirLocal(addr, server string, shadow func(net.Conn) net.Conn) {
	log.VLogf("TCP redirect not supported")
}

func redir6Local(addr, server string, shadow func(net.Conn) net.Conn) {
	log.VLogf("TCP6 redirect not supported")
}
