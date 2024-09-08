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
	"os"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration"
	"github.com/ajabep/unmtlsproxy/internal/httpproxy"
	"github.com/ajabep/unmtlsproxy/internal/log"
	"github.com/ajabep/unmtlsproxy/internal/tcpproxy"
)

func main() {
	cfg, err := configuration.NewConfiguration()
	if err != nil {
		log.Fatal("Failed to load configuration", "err", err)
	}

	time.Local = time.UTC

	var cliSessionCache tls.ClientSessionCache = nil
	if !cfg.DisableSocketReusing {
		cliSessionCache = tls.NewLRUClientSessionCache(10)
	}

	var w io.Writer = nil

	if cfg.UnsafeKeyLogPath != "" {
		w, err = os.OpenFile(cfg.UnsafeKeyLogPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_SYNC, os.ModePerm)
		if err != nil {
			log.Fatal("Unable to open the key log path", "err", err)
		}
	}

	tlsConfig := &tls.Config{
		// Server
		RootCAs:            cfg.ServerCAPool,
		InsecureSkipVerify: !cfg.ServerCAVerify,

		// Client
		Certificates:           cfg.ClientCertificates,
		ClientSessionCache:     cliSessionCache,
		SessionTicketsDisabled: cliSessionCache != nil,

		// Exchange
		KeyLogWriter:  w,
		Renegotiation: tls.RenegotiateFreelyAsClient,
	}

	switch cfg.Mode {
	case "http":
		httpproxy.Start(cfg, tlsConfig)
	case "tcp":
		tcpproxy.Start(cfg, tlsConfig)
	}
}
