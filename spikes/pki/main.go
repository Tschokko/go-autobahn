package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/tschokko/autobahn/spikes/pki/pkiutil"
)

func main() {
	var create = flag.String("create", "client", "create ca, client, server")
	var cn = flag.String("cn", "", "common name")
	var certFilename = flag.String("cert", "", "certificate file")
	var keyFilename = flag.String("key", "", "private key file")
	var crlFilename = flag.String("crl", "", "certificate file")
	var caCertFilename = flag.String("cacert", "", "ca certificate file")
	var caKeyFilename = flag.String("cakey", "", "ca private key file")

	flag.Parse()

	switch *create {
	case "ca":
		handleCreateCA(*cn, *certFilename, *keyFilename, *caCertFilename, *caKeyFilename)
		return
	case "crl":
		handleCreateCRL(*crlFilename, *caCertFilename, *caKeyFilename)
		return
	case "client":
		handleCreateClient(*cn, *certFilename, *keyFilename, *caCertFilename, *caKeyFilename)
		return
	case "server":
		handleCreateServer(*cn, *certFilename, *keyFilename, *caCertFilename, *caKeyFilename)
		return
	}

	/*createCRL("./icom_oam_gen1_validation_ca.crl.pem",
	"./icom_oam_gen1_validation_ca.crt.pem", "./icom_oam_gen1_validation_ca.key.pem")*/
}

func handleCreateCA(cn, certFilename, keyFilename, caCertFilename, caKeyFilename string) {
	if caCertFilename == "" {
		if err := pkiutil.CreateCA(cn, certFilename, keyFilename); err != nil {
			fmt.Println("failed to create ca: ", err)
			return
		}
	} else {
		if err := pkiutil.CreateSubCA(cn, certFilename, keyFilename, caCertFilename, caKeyFilename); err != nil {
			fmt.Println("failed to create ca: ", err)
			return
		}
	}
	fmt.Println("successfully created ca")
}

func handleCreateCRL(crlFilename, caCertFilename, caKeyFilename string) {
	if err := pkiutil.CreateCRL(crlFilename, caCertFilename, caKeyFilename); err != nil {
		fmt.Println("failed to create crl: ", err)
		return
	}
	fmt.Println("successfully created crl")
}

func handleCreateClient(cn, certFilename, keyFilename, caCertFilename, caKeyFilename string) {
	if err := pkiutil.CreateClientCertificate(cn, time.Now().AddDate(1, 0, 0), certFilename, keyFilename,
		caCertFilename, caKeyFilename); err != nil {
		fmt.Println("failed to create client certificate: ", err)
		return
	}

	fmt.Println("successfully created client certificate")
}

func handleCreateServer(cn, certFilename, keyFilename, caCertFilename, caKeyFilename string) {
	if err := pkiutil.CreateServerCertificate(cn, time.Now().AddDate(1, 0, 0), certFilename, keyFilename,
		caCertFilename, caKeyFilename); err != nil {
		fmt.Println("failed to create server certificate: ", err)
		return
	}

	fmt.Println("successfully created server certificate")
}
