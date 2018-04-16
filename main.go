package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/riobard/go-shadowsocks2/client"
	"github.com/riobard/go-shadowsocks2/core"
	"github.com/riobard/go-shadowsocks2/server"
)

func main() {

	var flags struct {
		Client     spaceSeparatedList
		Server     spaceSeparatedList
		TCPTun     pairList
		UDPTun     pairList
		Socks      string
		RedirTCP   string
		RedirTCP6  string
		UDPTimeout time.Duration
	}

	listCiphers := flag.Bool("cipher", false, "List supported ciphers")
	flag.Var(&flags.Server, "s", "server listen url")
	flag.Var(&flags.Client, "c", "client connect url")
	flag.Var(&flags.TCPTun, "tcptun", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.Var(&flags.UDPTun, "udptun", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.DurationVar(&flags.UDPTimeout, "udptimeout", 120*time.Second, "UDP tunnel timeout")
	flag.Parse()

	if *listCiphers {
		println(strings.Join(core.ListCipher(), " "))
		return
	}

	if len(flags.Client) == 0 && len(flags.Server) == 0 {
		flag.Usage()
		return
	}

	const udpBufSize = 64 * 1024
	var udpBufPool = sync.Pool{New: func() interface{} { return make([]byte, udpBufSize) }}
	if len(flags.Client) > 0 { // client mode
		if len(flags.UDPTun) > 0 { // use first server for UDP
			addr, cipher, password, err := core.ParseURL(flags.Client[0])
			if err != nil {
				log.Fatal(err)
			}

			ciph, err := core.PickCipher(cipher, nil, password)
			if err != nil {
				log.Fatal(err)
			}
			for _, p := range flags.UDPTun {
				go client.UDPLocal(p[0], addr, p[1], ciph.PacketConn, flags.UDPTimeout, &udpBufPool)
			}
		}

		d, err := client.Fastdialer(flags.Client...)
		if err != nil {
			log.Fatalf("failed to create dialer: %v", err)
		}

		if len(flags.TCPTun) > 0 {
			for _, p := range flags.TCPTun {
				go client.TCPTun(p[0], p[1], d)
			}
		}

		if flags.Socks != "" {
			go client.SocksLocal(flags.Socks, d)
		}

		if flags.RedirTCP != "" {
			go client.RedirLocal(flags.RedirTCP, d)
		}

		if flags.RedirTCP6 != "" {
			go client.Redir6Local(flags.RedirTCP6, d)
		}
	}

	if len(flags.Server) > 0 { // server mode
		for _, each := range flags.Server {
			addr, cipher, password, err := core.ParseURL(each)
			if err != nil {
				log.Fatal(err)
			}

			ciph, err := core.PickCipher(cipher, nil, password)
			if err != nil {
				log.Fatal(err)
			}

			go server.UDPRemote(addr, ciph.PacketConn, flags.UDPTimeout, &udpBufPool)
			go server.TCPRemote(addr, ciph.StreamConn)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

type pairList [][2]string // key1=val1,key2=val2,...

func (l pairList) String() string {
	s := make([]string, len(l))
	for i, pair := range l {
		s[i] = pair[0] + "=" + pair[1]
	}
	return strings.Join(s, ",")
}
func (l *pairList) Set(s string) error {
	for _, item := range strings.Split(s, ",") {
		pair := strings.Split(item, "=")
		if len(pair) != 2 {
			return nil
		}
		*l = append(*l, [2]string{pair[0], pair[1]})
	}
	return nil
}

type spaceSeparatedList []string

func (l spaceSeparatedList) String() string { return strings.Join(l, " ") }
func (l *spaceSeparatedList) Set(s string) error {
	*l = strings.Split(s, " ")
	return nil
}
