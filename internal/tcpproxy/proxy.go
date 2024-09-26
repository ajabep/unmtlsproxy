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

package tcpproxy

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/signal"

	"github.com/ajabep/unmtlsproxy/internal/configuration"
	"github.com/ajabep/unmtlsproxy/internal/log"
)

type proxy struct {
	from      configuration.Addr
	to        configuration.Addr
	tlsConfig *tls.Config
}

func newProxy(from, to configuration.Addr, tlsConfig *tls.Config) *proxy {
	return &proxy{
		from:      from,
		to:        to,
		tlsConfig: tlsConfig,
	}
}

// Start the proxy. Is blocking!
func (p *proxy) start(ctx context.Context) error {
	log.Debug("Binding port", "listening addr", p.from)
	listener, err := net.Listen("tcp", p.from.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		select {

		default:
			if connection, err := listener.Accept(); err == nil {
				log.Debug("Accepting a new connection", "listening addr", p.from)
				go p.handle(ctx, connection)
			}

		case <-ctx.Done():
			log.Debug("Closing the bound port", "listeningAddr", p.from)
			return nil
		}
	}
}

func (p *proxy) handle(ctx context.Context, connection net.Conn) {
	defer connection.Close()

	log.Debug("Opening a socket to the backend", "destinationAddr", p.to)
	remote, err := tls.Dial("tcp", p.to.String(), p.tlsConfig)
	if err != nil {
		log.Error("Error connecting the backend", "err", err, "backend", p.to)
		_, _ = connection.Write([]byte(err.Error()))
		return
	}
	defer remote.Close()

	subctx, cancel := context.WithCancel(ctx)
	go p.copy(subctx, cancel, remote, connection)
	go p.copy(subctx, cancel, connection, remote)

	<-subctx.Done()
	log.Debug("Closing the socket")
}

func (p *proxy) copy(ctx context.Context, cancel context.CancelFunc, from, to net.Conn) {
	defer cancel()

	var n int
	var err error
	buffer := make([]byte, 1024)

	select {

	default:
		for {
			n, err = from.Read(buffer)
			if err != nil {
				return
			}

			_, err = to.Write(buffer[:n])
			if err != nil {
				return
			}
		}

	case <-ctx.Done():
		return
	}
}

// Start starts the proxy
func Start(cfg *configuration.Configuration, tlsConfig *tls.Config) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := newProxy(cfg.ParsedListen, cfg.ParsedBackend, tlsConfig).start(ctx); err != nil {
			log.Fatal("Unable to start proxy", "err", err, "listen", cfg.ParsedListen, "backend", cfg.ParsedBackend)
		}
	}()

	log.Info("MTLSProxy is ready", "mode", cfg.Mode, "listen", cfg.ParsedListen, "backend", cfg.ParsedBackend)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
	log.Debug("Leaving!")
}
