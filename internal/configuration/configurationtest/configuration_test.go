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

	configs := []map[string]string{
		{
			"backend":  "client.badssl.com:443",
			"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
			"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
			"mode":     "http",
		},
	}
	for _, config := range configs {
		_, err = LoadNewConfiguration(config)
		if err != nil {
			t.Errorf("The Configuration loading failed while it was not supposed to fail: %s", err)
		}
	}
}
