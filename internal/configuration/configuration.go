// Copyright 2024 Ajabep
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package configuration is a small package for handling configuration
package configuration

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"go.aporeto.io/addedeffect/lombric"
	"go.aporeto.io/tg/tglib"
)

// Configuration hold the service configuration.
type Configuration struct {
	Backend                  string `mapstructure:"backend"                desc:"destination host"                                                                                                              required:"true"`
	ServerCAPoolPath         string `mapstructure:"server-ca"              desc:"Path the CAs used to verify server certificate. If not set, does not verify the server certificate."                           default:""`
	ListenAddress            string `mapstructure:"listen"                 desc:"Listening address"                                                                                                             default:":443"`
	ClientCertificateKeyPath string `mapstructure:"cert-key"               desc:"Path to the client certificate key"                                                                                            required:"true"`
	ClientCertificatePath    string `mapstructure:"cert"                   desc:"Path to the client certificate"                                                                                                required:"true"`
	Mode                     string `mapstructure:"mode"                   desc:"Proxy mode"                                                                                                                    default:"tcp" allowed:"tcp,http"`
	LogFormat                string `mapstructure:"log-format"             desc:"Log format"                                                                                                                    default:"console"`
	LogLevel                 string `mapstructure:"log-level"              desc:"Log level"                                                                                                                     default:"info"`
	UnsafeKeyLogPath         string `mapstructure:"unsafe-key-log-path"    desc:"[UNSAFE] Path of the file where session keys are dumped. Useful for debugging"                                                 default:""`
	DisableSocketReusing     bool   `mapstructure:"disable-socket-reusing" desc:"Disable the TLS socket reusing. Useful for debugging the HTTP mode. Not valid with the TCP mode (1 TCP socket = 1 TLS socket)" default:"false"`

	ServerCAPool       *x509.CertPool
	ClientCertificates []tls.Certificate
	ServerCAVerify     bool
}

// Prefix returns the configuration prefix.
func (c *Configuration) Prefix() string { return "unmtlsproxy" }

// PrintVersion prints the current version.
func (c *Configuration) PrintVersion() {
	fmt.Printf("unmtlsproxy - %s\n", "1.0")
}

// NewConfiguration returns a new configuration.
func NewConfiguration() *Configuration {

	c := &Configuration{}
	lombric.Initialize(c)

	listenUrl, err := url.Parse("http://" + c.ListenAddress)
	if err != nil {
		panic(err)
	}
	if port := listenUrl.Port(); port == "" {
		panic("Invalid Listen format. Use `hostname:port`.")
	} else if portInt, err := strconv.Atoi(port); err != nil {
		panic(err)
	} else if portInt <= 0 {
		panic("Invalid Listening Port. Too low.")
	} else if portInt > 65535 {
		panic("Invalid Listening Port. Too High. We use TCP.")
	}

	if c.Mode == "tcp" {
		if c.DisableSocketReusing {
			panic("Option 'disable-socket-reusing' is forbidden in TCP mode. Socket reusing cannot being enabled, option is useless")
		}
		c.DisableSocketReusing = true
	}

	c.ServerCAVerify = c.ServerCAPoolPath != ""
	if c.ServerCAVerify {
		data, err := os.ReadFile(c.ServerCAPoolPath)
		if err != nil {
			panic(err)
		}
		c.ServerCAPool = x509.NewCertPool()
		c.ServerCAPool.AppendCertsFromPEM(data)
	}

	certs, key, err := tglib.ReadCertificatePEMs(c.ClientCertificatePath, c.ClientCertificateKeyPath, "")
	if err != nil {
		panic(err)
	}

	tc, err := tglib.ToTLSCertificates(certs, key)
	if err != nil {
		panic(err)
	}
	c.ClientCertificates = append(c.ClientCertificates, tc)

	return c
}
