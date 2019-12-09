package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"

	openvpn "github.com/stamp/go-openvpn"
)

func newOpenVPNServer() *openvpn.Process {
	p := openvpn.NewProcess()
	c := openvpn.NewConfig()

	// c.Set("mode", "server")
	c.Set("port", strconv.Itoa(9443))
	c.Protocol("tcp-server")
	c.Device("tun")
	c.Set("topology", "subnet")
	c.IpPool("100.127.0.0/22")
	c.Set("server-ipv6", "2a03:4000:6:11cd:bbbb::/112")

	c.KeepAlive(10, 60)
	c.PingTimerRemote()
	c.PersistTun()
	c.PersistKey()

	// Security
	c.Set("auth", "SHA512")
	c.Set("cipher", "AES-256-CBC")
	c.Flag("comp-lzo")

	// SSL
	c.Flag("tls-server")

	c.Set("ca", "./ssl/ca/ca.crt")
	// c.Set("crl-verify", ca.GetCRLPath())
	c.Set("cert", "./ssl/server/server.crt")
	c.Set("key", "./ssl/server/server.key")
	c.Set("dh", "./ssl/dh2048.pem")

	// TLS-Auth
	c.Set("tls-auth", "./ssl/ta.key 0")
	c.Set("tls-version-min", "1.2")
	c.Set("tls-cipher", "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256")

	// Autobahn plugin
	c.Set("plugin", "/home/tlx3m3j/src/github.com/tschokko/autobahn-plugin/bin/autobahn-plugin.so")

	p.SetConfig(c)
	return p
}

func main() {
	// Create an instance of the openvpn struct
	// p := openvpn.NewStaticKeyServer("pre-shared.key", "server.json")
	// p := openvpn.NewSslServer(ca, cert, dh, ta, "server.json")
	p := newOpenVPNServer()

	// Install our signal handler before starting the server process
	interruptCh := make(chan os.Signal, 1)
	signal.Notify(interruptCh, os.Interrupt)

	// Start the openvpn process. Note that this method do not block so the program will continue at once.
	p.Start()

	// Listen for events
	for {
		select {
		case event := <-p.Events:
			log.Println("Event: ", event.Name, "(", event.Args, ")")
		case <-interruptCh:
			if err := p.Shutdown(); err != nil {
				log.Println("ERROR: ", err)
			}
		case <-p.Stopped:
			return
		}
	}
}
