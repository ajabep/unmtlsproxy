package configurationtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration"
	"github.com/spf13/pflag"
)

func GenerateCertificate(certificatePath string, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	pvBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: pvBytes,
	})

	tml := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SerialNumber: big.NewInt(123123),
		Subject: pkix.Name{
			CommonName:   "Hugging Department",
			Organization: []string{"BlaHaj Corp."},
		},
		PublicKeyAlgorithm: x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// Generate a pem block with the certificate
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	certificateOut, err := os.OpenFile(certificatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	if _, err := keyOut.Write(keyPem); err != nil {
		return err
	}
	if _, err := certificateOut.Write(certPem); err != nil {
		return err
	}
	return nil
}

func SetupConfigurationEnv(args map[string]string) {
	for k, v := range args {
		k = strings.TrimPrefix(k, "--")
		k = strings.ToUpper(k)
		k = "UNMTLSPROXY_" + k
		k = strings.ReplaceAll(k, " ", "_")
		k = strings.ReplaceAll(k, "-", "_")

		os.Setenv(k, v)
	}
}

func ResetFlags() {
	pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
}

func LoadNewConfiguration(args map[string]string) (*configuration.Configuration, error) {
	ResetFlags()
	SetupConfigurationEnv(args)
	return configuration.NewConfiguration()
}

func GetExampleDir(level int) (string, error) {
	currentDir, err := os.Getwd() // os.Executable()
	if err != nil {
		return "", err
	}
	currentDir, err = filepath.Abs(currentDir)
	if err != nil {
		return "", err
	}
	for range level {
		currentDir = filepath.Dir(currentDir)
	}
	return filepath.Join(currentDir, "example"), nil
}

func NewListener() (string, *netip.Addr, uint16, error) {
	var minPort, maxPort uint16 = 5000, 65535
	addr, err := netip.ParseAddr("127.0.0.1")
	if err != nil {
		return "", nil, 0, err
	}
	for {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(maxPort-minPort)))
		if err != nil {
			return "", nil, 0, err
		}
		port := uint16(x.Uint64())
		port += minPort

		l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr.String(), port))
		if err != nil {
			continue
		}
		l.Close()
		return fmt.Sprintf("%s:%d", addr.String(), port), &addr, uint16(port), nil
	}
}
