package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"time"
)

func GenerateCertificate(clientAuth bool, certOut, privOut io.Writer) ([]byte, []byte, error) {
	privDerBytes, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(120)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	templateCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Unit Test. DO NOT USE."},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              0,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,

		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	templateCert.KeyUsage |= x509.KeyUsageDigitalSignature
	if clientAuth {
		templateCert.ExtKeyUsage = append(templateCert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	} else {
		templateCert.ExtKeyUsage = append(templateCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		templateCert.IsCA = true
		templateCert.KeyUsage |= x509.KeyUsageCertSign
	}

	certDerBytes, err := x509.CreateCertificate(rand.Reader, &templateCert, &templateCert, privDerBytes.Public(), privDerBytes)
	if err != nil {
		return nil, nil, err
	}

	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDerBytes})
	if _, err := certOut.Write(certPemBytes); err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privDerBytes)
	if err != nil {
		return nil, nil, err
	}

	privPemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if _, err := privOut.Write(privPemBytes); err != nil {
		return nil, nil, err
	}

	return certPemBytes, privPemBytes, nil
}
