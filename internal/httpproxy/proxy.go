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
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration"
)

func makeHandleHTTP(dest string, tlsConfig *tls.Config) func(w http.ResponseWriter, req *http.Request) {

	u, err := url.Parse(dest)
	if err != nil {
		log.Fatalf("Cannot parse the backend URI: %s", err)
	}

	switch u.Port() {
	default:
		if u.Scheme == "" {
			log.Fatalf("Cannot guess the Scheme for port %s", u.Port())
		}
	case "80":
		u.Scheme = "http"
	case "443":
		u.Scheme = "http"
	case "":
		switch u.Scheme {
		default:
			log.Fatalf("Cannot guess the default port for scheme %s", u.Scheme)
		case "http":
			u.Host += ":80"
		case "https":
			u.Host += ":443"
		case "":
			log.Fatal("Cannot guess the Scheme when no port is given")
		}
	}

	rewriteHost := u.Host
	rewriteSchema := u.Scheme

	hostAttr := u.Hostname() + ":" + u.Port()

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
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return func(w http.ResponseWriter, req *http.Request) {

		req.URL.Host = rewriteHost
		req.URL.Scheme = rewriteSchema

		// Update Host header
		//req.Header.Set("Host", hostHeader)
		req.Host = hostAttr

		resp, err := transport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		defer resp.Body.Close() // nolint: errcheck
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(resp.StatusCode)

		if _, err = io.Copy(w, resp.Body); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
}

// Start starts the proxy
func Start(cfg *configuration.Configuration, tlsConfig *tls.Config) {

	server := &http.Server{
		Addr:    cfg.ListenAddress,
		Handler: http.HandlerFunc(makeHandleHTTP(cfg.Backend, tlsConfig)),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalln("Unable to start proxy:", err)
		}
	}()

	log.Printf("MTLSProxy is ready. mode:%s listen:%s backend:%s ", cfg.Mode, cfg.ListenAddress, cfg.Backend)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
}
