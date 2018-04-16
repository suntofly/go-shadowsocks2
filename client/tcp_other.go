// +build !linux

package client

import "github.com/riobard/go-shadowsocks2/log"

func RedirLocal(addr string, d Dialer) {
	log.VLogf("TCP redirect not supported")
}

func Redir6Local(addr string, d Dialer) {
	log.VLogf("TCP6 redirect not supported")
}
