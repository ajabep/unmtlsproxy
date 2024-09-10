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
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"

	"github.com/ajabep/unmtlsproxy/internal/log"
	"go.aporeto.io/addedeffect/lombric"
	"go.aporeto.io/tg/tglib"
)

type Addr struct {
	Hostname string
	Port     uint16
}

func (a Addr) String() string {
	return fmt.Sprintf("%s:%d", a.Hostname, a.Port)
}

// Configuration hold the service configuration.
type Configuration struct {
	BackendAddress           string `mapstructure:"backend"                desc:"destination host. Format: host:port"                                                                                           required:"true"`
	ServerCAPoolPath         string `mapstructure:"server-ca"              desc:"Path the CAs used to verify server certificate. If not set, does not verify the server certificate."                           default:""`
	ListenAddress            string `mapstructure:"listen"                 desc:"Listening address"                                                                                                             default:":443"`
	ClientCertificateKeyPath string `mapstructure:"cert-key"               desc:"Path to the client certificate key"                                                                                            required:"true"`
	ClientCertificatePath    string `mapstructure:"cert"                   desc:"Path to the client certificate"                                                                                                required:"true"`
	Mode                     string `mapstructure:"mode"                   desc:"Proxy mode"                                                                                                                    default:"tcp" allowed:"tcp,http"`
	LogLevel                 string `mapstructure:"log-level"              desc:"Log level"                                                                                                                     default:"info" allowed:"debug,info"`
	UnsafeKeyLogPath         string `mapstructure:"unsafe-key-log-path"    desc:"[UNSAFE] Path of the file where session keys are dumped. Useful for debugging"                                                 default:""`
	DisableSocketReusing     bool   `mapstructure:"disable-socket-reusing" desc:"Disable the TLS socket reusing. Useful for debugging the HTTP mode. Not valid with the TCP mode (1 TCP socket = 1 TLS socket)" default:"false"`

	ServerCAPool       *x509.CertPool
	ClientCertificates []tls.Certificate
	ServerCAVerify     bool
	ParsedBackend      Addr
	ParsedListen       Addr
}

// Prefix returns the configuration prefix.
func (c *Configuration) Prefix() string { return "unmtlsproxy" }

// PrintVersion prints the current version.
// TODO make the version number dynamic
func (c *Configuration) PrintVersion() {
	fmt.Printf("unmtlsproxy - %s\n", "1.2")
}

var (
	ErrInvalidListenFormat         = errors.New("invalid listen format. Use `hostname:port`")
	ErrInvalidPortTooLow           = errors.New("invalid listening port: too low")
	ErrInvalidPortTooHigh          = errors.New("invalid listening port: too high")
	ErrForbiddenDisableSocketUsing = errors.New("option 'disable-socket-reusing' is forbidden in TCP mode. Socket reusing cannot being enabled, option is useless")
)

// NewConfiguration returns a new configuration.
func NewConfiguration() (*Configuration, error) {
	c := &Configuration{}
	lombric.Initialize(c)

	lvl := slog.LevelDebug
	if c.LogLevel == "info" {
		lvl = slog.LevelInfo
	}
	log.InitDefault(lvl)

	log.Debug("Parsing the listening address", "listeningAddr", c.ListenAddress)
	listenUrl, err := url.Parse("http://" + c.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the listening address: %w", err)
	}
	if port := listenUrl.Port(); port == "" {
		return nil, ErrInvalidListenFormat
	} else if portInt, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("invalid listening port format: %w", err)
	} else if portInt <= 0 {
		return nil, fmt.Errorf("cannot parse the listening address: %w", ErrInvalidPortTooLow)
	} else if portInt > 65535 {
		return nil, fmt.Errorf("cannot parse the listening address: %w", ErrInvalidPortTooHigh)
	} else {
		c.ParsedListen = Addr{
			Hostname: listenUrl.Hostname(),
			Port:     uint16(portInt),
		}
	}

	log.Debug("Parsing the backend address", "backendAddr", c.ParsedBackend)
	bckndUrl, err := url.Parse("tcp://" + c.BackendAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the backend address: %w", err)
	}
	if port := bckndUrl.Port(); port == "" {
		return nil, ErrInvalidListenFormat
	} else if portInt, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("invalid backend port format: %w", err)
	} else if portInt <= 0 {
		return nil, fmt.Errorf("cannot parse the backend address: %w", ErrInvalidPortTooLow)
	} else if portInt > 65535 {
		return nil, fmt.Errorf("cannot parse the backend address: %w", ErrInvalidPortTooHigh)
	} else {
		c.ParsedBackend = Addr{
			Hostname: bckndUrl.Hostname(),
			Port:     uint16(portInt),
		}
	}

	log.Debug("Parsing the disable socket reusing option", "mode", c.Mode, "disableSocketReusing", c.DisableSocketReusing)
	if c.Mode == "tcp" {
		if c.DisableSocketReusing {
			return nil, ErrForbiddenDisableSocketUsing
		}
		c.DisableSocketReusing = true
	}

	log.Debug("Parsing the server CA", "serverCAPoolPath", c.ServerCAPoolPath, "serverCAVerify", c.ServerCAVerify)
	c.ServerCAVerify = c.ServerCAPoolPath != ""
	if c.ServerCAVerify {
		data, err := os.ReadFile(c.ServerCAPoolPath)
		if err != nil {
			return nil, err
		}
		c.ServerCAPool = x509.NewCertPool()
		c.ServerCAPool.AppendCertsFromPEM(data)
	}
	log.Debug("Parsed the verify status", "serverCAVerify", c.ServerCAVerify)

	log.Debug("Reading the client certificate and keys", "ClientCertificatePath", c.ClientCertificatePath, "ClientCertificateKeyPath", c.ClientCertificateKeyPath)
	certs, key, err := tglib.ReadCertificatePEMs(c.ClientCertificatePath, c.ClientCertificateKeyPath, "")
	if err != nil {
		return nil, err
	}

	tc, err := tglib.ToTLSCertificates(certs, key)
	if err != nil {
		return nil, err
	}
	c.ClientCertificates = append(c.ClientCertificates, tc)

	return c, nil
}
