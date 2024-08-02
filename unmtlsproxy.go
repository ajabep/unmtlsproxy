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

package main

import (
	"crypto/tls"
	"io"
	"log"
	"os"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration"
	"github.com/ajabep/unmtlsproxy/internal/httpproxy"
	"github.com/ajabep/unmtlsproxy/internal/tcpproxy"
)

func main() {

	cfg := configuration.NewConfiguration()

	time.Local = time.UTC

	cliSessionCache := tls.NewLRUClientSessionCache(10)

	var w io.Writer = nil

	if cfg.UnsecureKeyLogPath != "" {
		if w2, err := os.OpenFile(cfg.UnsecureKeyLogPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_SYNC, os.ModePerm); err != nil {
			log.Fatalln("Unable to open the key log path:", err)
		} else {
			w = w2 // If setting up w and err with a `:=`, it will create a temp var
		}
	}

	tlsConfig := &tls.Config{
		// Server
		RootCAs:            cfg.ServerCAPool,
		InsecureSkipVerify: !cfg.ServerCAVerify,

		// Client
		Certificates:       cfg.ClientCertificates,
		ClientSessionCache: cliSessionCache,

		// Exchange
		KeyLogWriter:  w,
		Renegotiation: tls.RenegotiateFreelyAsClient,

		/// OLD
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS12,
		SessionTicketsDisabled:   true,
		PreferServerCipherSuites: true,

		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	switch cfg.Mode {
	case "http":
		httpproxy.Start(cfg, tlsConfig)
	case "tcp":
		tcpproxy.Start(cfg, tlsConfig)
	}
}
