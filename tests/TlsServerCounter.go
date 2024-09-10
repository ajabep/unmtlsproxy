package tests

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration/configurationtest"
)

type TlsServerCounter struct {
	CertServerFilePath string
	KeyServerFilePath  string
	CertClientFilePath string
	KeyClientFilePath  string

	ClientKeyPair tls.Certificate
	ServerKeyPair tls.Certificate

	addr *netip.Addr
	port uint16

	tlsConfig *tls.Config

	httpMode bool
}

const (
	httpRefLine string = "GET / HTTP/"
	tcpRefLine         = "R"
)

/**
 * Creates and a start a TLS server returning the "index" of the request as a body response.
 * It also generate a random and temporary certs and keys.
 */
func NewStartedTlsServerCounter(httpMode bool) (*TlsServerCounter, error) {
	srv := TlsServerCounter{
		httpMode: httpMode,
	}

	certServerFile, err := os.CreateTemp("", "unmtlsproxy_unit_tests_cert_server_*")
	if err != nil {
		return nil, err
	}
	privServerFile, err := os.CreateTemp("", "unmtlsproxy_unit_tests_priv_server_*")
	if err != nil {
		return nil, err
	}
	certClientFile, err := os.CreateTemp("", "unmtlsproxy_unit_tests_cert_client_*")
	if err != nil {
		return nil, err
	}
	privClientFile, err := os.CreateTemp("", "unmtlsproxy_unit_tests_priv_client_*")
	if err != nil {
		return nil, err
	}
	go func() {
		defer os.Remove(certServerFile.Name())
		defer os.Remove(privServerFile.Name())
		defer os.Remove(certClientFile.Name())
		defer os.Remove(privClientFile.Name())
		for {
			time.Sleep(999 * time.Hour)
		}
	}()

	certServer, privServer, err := GenerateCertificate(false, certServerFile, privServerFile)
	if err != nil {
		return nil, err
	}
	certClient, privClient, err := GenerateCertificate(true, certClientFile, privClientFile)
	if err != nil {
		return nil, err
	}

	if err := certServerFile.Close(); err != nil {
		return nil, err
	}
	if err := privServerFile.Close(); err != nil {
		return nil, err
	}
	if err := certClientFile.Close(); err != nil {
		return nil, err
	}
	if err := privClientFile.Close(); err != nil {
		return nil, err
	}
	srv.CertServerFilePath = certServerFile.Name()
	srv.KeyServerFilePath = privServerFile.Name()
	srv.CertClientFilePath = certClientFile.Name()
	srv.KeyClientFilePath = privClientFile.Name()

	srv.ServerKeyPair, err = tls.X509KeyPair(certServer, privServer)
	if err != nil {
		return nil, err
	}
	srv.ClientKeyPair, err = tls.X509KeyPair(certClient, privClient)
	if err != nil {
		return nil, err
	}

	_, srv.addr, srv.port, err = configurationtest.NewListener()
	if err != nil {
		return nil, err
	}

	srv.tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{srv.ServerKeyPair},
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}
	listenerTcp, err := net.ListenTCP(
		"tcp4",
		srv.TcpAddr(),
	)
	if err != nil {
		return nil, err
	}
	listenerTls := tls.NewListener(
		listenerTcp,
		srv.tlsConfig,
	)

	go func(listener net.Listener) {
		// Accept TCP conn
		for {
			conn, err := listener.Accept()
			if err != nil {
				panic(err)
			}

			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				if err := tlsConn.Handshake(); err != nil {
					// If the handshake failed due to the client not speaking
					// TLS, assume they're speaking plaintext HTTP and write a
					// 400 response on the TLS conn's underlying net.Conn.
					var reason string
					re, ok := err.(tls.RecordHeaderError)
					if ok && re.Conn != nil && bytes.Equal(re.RecordHeader[:5], []byte("GET /")) {
						io.WriteString(re.Conn, "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
						re.Conn.Close()
						reason = "client sent an HTTP request to an HTTPS server"
					} else {
						reason = err.Error()
					}
					io.WriteString(re.Conn, fmt.Sprintf("HTTP/1.0 400 Bad Request\r\n\r\nhttp: TLS handshake error from %s: %v\n", tlsConn.RemoteAddr(), reason))
					fmt.Printf("http: TLS handshake error from %s: %v", tlsConn.RemoteAddr(), reason)
					return
				}
			}

			go func(conn net.Conn) {
				defer conn.Close()

				// For each TCP conn
				nbReq := NewSyncedUint()

				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					line := scanner.Text()
					line = strings.TrimSpace(line)
					refLine := tcpRefLine
					if srv.httpMode {
						refLine = httpRefLine
					}
					if strings.Contains(line, refLine) {
						reqNum := nbReq.GetInc()
						var response string
						if srv.httpMode {
							response = srv.forgeHttpResponse(reqNum)
						} else {
							response = srv.forgeTcpResponse(reqNum % 10)
						}
						if _, err := conn.Write([]byte(response)); err != nil {
							panic(err)
						}
					}
				}

				if err := scanner.Err(); err != nil {
					if e2, ok := err.(*net.OpError); ok && e2.Op == "read" {
						return
					}
					panic(err)
				}
			}(conn)
		}
	}(listenerTls)

	return &srv, nil
}

func (srv *TlsServerCounter) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(
		*srv.addr,
		srv.port,
	)
}

func (srv *TlsServerCounter) TcpAddr() *net.TCPAddr {
	return net.TCPAddrFromAddrPort(srv.AddrPort())
}

func (srv *TlsServerCounter) AddrString() string {
	return fmt.Sprintf("%s:%d", srv.addr, srv.port)
}

func (srv *TlsServerCounter) Backend() string {
	return fmt.Sprintf("%s:%d", srv.addr, srv.port)
}

func (srv *TlsServerCounter) Mode() string {
	if srv.httpMode {
		return "http"
	}
	return "tcp"
}

func (srv *TlsServerCounter) forgeHttpResponse(id uint) string {
	respBody := fmt.Sprintf("%d", id)
	response := fmt.Sprintf(
		`HTTP/1.1 200 OK
Content-Length: %d
Content-Type: text/plain; charset=utf-8

%s`,
		len(respBody),
		respBody,
	)
	return strings.Replace(response, "\n", "\r\n", -1)
}

func (srv *TlsServerCounter) forgeTcpResponse(id uint) string {
	return fmt.Sprintf("%d\n", id)
}
