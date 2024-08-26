package configurationtest

import (
	"path/filepath"
	"testing"
)

func TestNewConfigurationValidMinimalist(t *testing.T) {
	exampleDir, err := GetExampleDir(3)
	if err != nil {
		panic(err)
	}

	config := map[string]string{
		"backend":  "https://client.badssl.com",
		"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
		"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
		"mode":     "http",
	}

	_ = LoadNewConfiguration(config)
}

// func TestNewConfigurationValidClientCertificatePassword(t *testing.T) {
// 	exampleDir, err := GetExampleDir(3)
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	config := map[string]string{
// 		"backend":       "https://client.badssl.com",
// 		"cert":          filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
// 		"cert-key":      filepath.Join(exampleDir, "badssl.com-client.key.pem"),
// 		"cert-key-pass": "badssl.com",
// 		"mode":          "http",
// 	}
//
// 	_ = LoadNewConfiguration(config)
// }
