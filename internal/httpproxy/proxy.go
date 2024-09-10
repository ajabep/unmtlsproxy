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

package httpproxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration"
	"github.com/ajabep/unmtlsproxy/internal/log"
)

func makeHandleHTTP(dest configuration.Addr, tlsConfig *tls.Config, reuseSockets bool) func(w http.ResponseWriter, req *http.Request) {
	log.Debug("Parsing destination end", "destination", dest)
	if dest.Port == 80 {
		log.Fatal("Cannot use an HTTP backend")
	}

	rewriteHost := dest.String()
	rewriteSchema := "https"
	hostAttr := dest.Hostname
	if dest.Port != 443 {
		hostAttr = dest.String()
	}

	log.Debug("Building the TLS client configuration")
	maxIdleConns := 1
	idleConnTimeout := 1 * time.Microsecond
	disableKeepAlives := !reuseSockets
	if reuseSockets {
		maxIdleConns = 100
		idleConnTimeout = 90 * time.Second
	}

	// It establishes network connections as needed
	// and caches them for reuse by subsequent calls. It uses HTTP proxies
	// as directed by the environment variables HTTP_PROXY, HTTPS_PROXY
	// and NO_PROXY (or the lowercase versions thereof).
	var transport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          maxIdleConns,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     disableKeepAlives,
	}

	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("Received a request", "req", req)

		if !reuseSockets {
			if tr, ok := transport.(*http.Transport); ok {
				log.Debug("Closing old idle connections")
				tr.CloseIdleConnections()
			}
		}

		log.Debug("Edit the request", "req", req)
		req.URL.Host = rewriteHost
		req.URL.Scheme = rewriteSchema
		req.Host = hostAttr

		log.Debug("Sending the edited request", "req", req)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			log.Error("Cannot RoundTrip a request", "err", err, "req", req)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		defer resp.Body.Close()
		log.Debug("Sending back the headers", "resp", resp)
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		log.Debug("Sending HTTP code", "code", resp.StatusCode)
		w.WriteHeader(resp.StatusCode)

		log.Debug("Sending back the body")
		if _, err = io.Copy(w, resp.Body); err != nil {
			log.Error("Cannot send the response to the client of the proxy", "err", err, "resp", resp, "w", w)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
}

// Start starts the proxy
func Start(cfg *configuration.Configuration, tlsConfig *tls.Config) {
	server := &http.Server{
		Addr:    cfg.ParsedListen.String(),
		Handler: http.HandlerFunc(makeHandleHTTP(cfg.ParsedBackend, tlsConfig, !cfg.DisableSocketReusing)),
	}

	go func() {
		log.Debug("Listening the port", "listening", cfg.ParsedListen)
		if err := server.ListenAndServe(); err != nil {
			log.Fatal("Unable to start proxy", "err", err)
		}
	}()

	log.Info("MTLSProxy is ready", "mode", cfg.Mode, "listen", cfg.ParsedListen, "backend", cfg.ParsedBackend)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
	log.Debug("Leaving!")
}
