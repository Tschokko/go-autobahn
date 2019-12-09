package pkiutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func CreateClientCertificate(cn string, validTo time.Time, certFilename, keyFilename, caCertFilename, caKeyFilename string) error {
	// Load CA
	catls, err := tls.LoadX509KeyPair(caCertFilename, caKeyFilename)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		return err
	}

	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return err
	}

	// Prepare certificate
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: []string{"VPN"},
			Organization:       []string{"tschokko.de"},
		},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              validTo,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	// Generate key
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	// Compute the subject key identifier based on the public key
	ski, err := computeSKI(pub)
	if err != nil {
		return err
	}
	cert.SubjectKeyId = ski

	// Sign the certificate
	certBin, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)

	// Public key
	certOut, err := os.OpenFile(certFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBin})
	certOut.Close()

	// Private key
	keyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut,
		&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}
