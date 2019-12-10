package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"

	openvpn "github.com/stamp/go-openvpn"
)

func newOpenVPNClient(cert, key string) *openvpn.Process {
	p := openvpn.NewProcess()
	c := openvpn.NewConfig()

	c.Flag("client")
	c.Set("port", strconv.Itoa(9443))
	c.Protocol("tcp-client")
	c.Device("tun")
	c.Remote("localhost", 9443)

	c.Set("resolv-retry", "infinite")
	c.Flag("nobind")

	c.PersistTun()
	c.PersistKey()

	// Security
	c.Set("auth", "SHA512")
	c.Set("cipher", "AES-256-CBC")
	c.Flag("comp-lzo")

	// SSL
	c.Set("ca", "./spikes/pki/root-ca.crt")
	// c.Set("crl-verify", ca.GetCRLPath())
	c.Set("cert", cert)
	c.Set("key", key)
	c.Set("dh", "./ssl/dh2048.pem")

	// TLS-Auth
	c.Set("remote-cert-tls", "server")
	c.Set("tls-auth", "./ssl/ta.key 1")
	c.Set("tls-version-min", "1.2")
	c.Set("tls-cipher", "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256")

	// Works only with UDP
	// c.Flag("explicit-exit-notify")

	p.SetConfig(c)
	return p
}

func main() {
	var cert = flag.String("cert", "", "certificate file")
	var key = flag.String("key", "", "private key file")

	flag.Parse()

	// Create an instance of the openvpn struct
	// p := openvpn.NewStaticKeyServer("pre-shared.key", "server.json")
	// p := openvpn.NewSslClient("192.168.209.197 1194", ca, cert, dh, ta, "client.json")
	p := newOpenVPNClient(*cert, *key)

	// Install our signal handler before starting the server process
	interruptCh := make(chan os.Signal, 1)
	signal.Notify(interruptCh, os.Interrupt)

	// Start the openvpn process. Note that this method do not block so the program will continue at once.
	if err := p.Start(); err != nil {
		panic(err)
	}

	// Listen for events
	for {
		select {
		case event := <-p.Events:
			log.Println("Event: ", event.Name, "(", event.Args, ")")
			if event.Name == "Disconnected" {
				return
			}
		case <-interruptCh:
			if err := p.Shutdown(); err != nil {
				log.Println("ERROR: ", err)
			}
		case <-p.Stopped:
			return
		}
	}
}
