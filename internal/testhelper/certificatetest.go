package testhelper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

var (
	root  CertTuple
	leaf  CertTuple
	root2 CertTuple
)

type CertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

func init() {
	setupCertificates()
}

func GetRootCertificate() CertTuple {
	return root
}

func GetLeafCertificate() CertTuple {
	return leaf
}

func GetRoot2Certificate() CertTuple {
	return root2
}

func setupCertificates() {
	root = getCertTuple("Notation Test Root", nil)
	leaf = getCertTuple("Notation Test Leaf Cert", &root)
	root2 = getCertTuple("Notation Test Root2", nil)
}

func getCertTuple(cn string, issuer *CertTuple) CertTuple {
	privKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	var certBytes []byte
	if issuer != nil {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				Organization: []string{"Notary"},
				Country:      []string{"US"},
				Province:     []string{"WA"},
				Locality:     []string{"Seattle"},
				CommonName:   cn,
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(0, 0, 1),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, issuer.Cert, &privKey.PublicKey, issuer.PrivateKey)
	} else {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Notary"},
				Country:      []string{"US"},
				Province:     []string{"WA"},
				Locality:     []string{"Seattle"},
				CommonName:   "Notation Test Root",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(0, 1, 0),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			MaxPathLen:            1,
			IsCA:                  true,
		}
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	}

	cert, _ := x509.ParseCertificate(certBytes)
	return CertTuple{
		Cert:       cert,
		PrivateKey: privKey,
	}
}
