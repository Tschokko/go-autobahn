package pkiutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/pkg/errors"
	"math/big"
	"os"
	"time"
)

func CreateCA(cn, certFilename, keyFilename string) error {
	notBefore := time.Unix(0, 0)
	notAfter := time.Now().AddDate(15, 0, 0)

	// 1.2.840.113549.1.9.1
	// emailOid := asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 1})

	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return errors.Wrap(err, "create ca failed to generate random serial")
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA384WithRSA,
		SerialNumber:       serialNumber, // big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: []string{"VPN"}, // , "Managed Services"
			Organization:       []string{"tschokko.de"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},                                                         // []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},       // []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, // | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment, // x509.KeyUsageDigitalSignature |
		BasicConstraintsValid: true,
	}

	// Add SAN
	/*extSubjectAltName := pkix.Extension{}
	extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
	extSubjectAltName.Critical = false
	extSubjectAltName.Value = []byte(`email:support@insys-tec.de`) // , URI:http://ca.dom.tld/
	cert.ExtraExtensions = []pkix.Extension{extSubjectAltName}*/

	// Create Key
	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	pub := &priv.PublicKey

	// Compute the subject key identifier based on the public key
	ski, err := computeSKI(pub)
	if err != nil {
		return errors.Wrap(err, "create ca failed to compute ski")
	}
	cert.SubjectKeyId = ski
	cert.AuthorityKeyId = ski

	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		return errors.Wrap(err, "create ca failed to create certificate")
	}

	// Public key
	certOut, err := os.OpenFile(certFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Wrap(err, "create ca failed to open certificate file")
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: raw})
	certOut.Close()

	// Private key
	keyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrap(err, "create ca failed to open private key file")
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

func CreateSubCA(cn, certFilename, keyFilename, caCertFilename, caKeyFilename string) error {
	// Load CA
	catls, err := tls.LoadX509KeyPair(caCertFilename, caKeyFilename)
	if err != nil {
		return errors.Wrap(err, "create sub ca failed to load ca key pair")
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "create sub ca failed to parse ca certificate")
	}

	notBefore := time.Unix(0, 0)
	notAfter := time.Now().AddDate(10, 0, 0)

	// 1.2.840.113549.1.9.1
	// emailOid := asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 1})

	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return errors.Wrap(err, "create sub ca failed to generate serial number")
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA384WithRSA,
		SerialNumber:       serialNumber, // big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: []string{"VPN"}, // , "Managed Services"
			Organization:       []string{"tschokko.de"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},                                                         // []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},       // []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, // | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment, // x509.KeyUsageDigitalSignature |
		BasicConstraintsValid: true,
	}

	// Add SAN
	/*extSubjectAltName := pkix.Extension{}
	extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
	extSubjectAltName.Critical = false
	extSubjectAltName.Value = []byte(`email:support@insys-tec.de`) // , URI:http://ca.dom.tld/
	cert.ExtraExtensions = []pkix.Extension{extSubjectAltName}*/

	// Create Key
	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	pub := &priv.PublicKey

	// Compute the subject key identifier based on the public key
	ski, err := computeSKI(pub)
	if err != nil {
		return errors.Wrap(err, "create sub ca failed to compute ski")
	}
	cert.SubjectKeyId = ski
	cert.AuthorityKeyId = ski

	raw, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "create sub ca failed to create certificate")
	}

	// Public key
	certOut, err := os.OpenFile(certFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Wrap(err, "create sub ca failed to open certificate file")
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: raw})
	certOut.Close()

	// Private key
	keyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrap(err, "create sub ca failed to open private key file")
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

func CreateCRL(crlFilename, caCertFilename, caKeyFilename string) error {
	// Load CA
	catls, err := tls.LoadX509KeyPair(caCertFilename, caKeyFilename)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		return err
	}

	now := time.Now()
	expiryTime := now.AddDate(0, 1, 0)
	rawCRL, err := ca.CreateCRL(rand.Reader, catls.PrivateKey, nil, time.Now(), expiryTime)
	if err != nil {
		return err
	}

	crlOut, err := os.OpenFile(crlFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	pem.Encode(crlOut, &pem.Block{Type: "X509 CRL", Bytes: rawCRL})
	crlOut.Close()

	return nil
}
