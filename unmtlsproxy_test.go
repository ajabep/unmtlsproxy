package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration/configurationtest"
	"github.com/ajabep/unmtlsproxy/tests"
)

type HttpStatus int

const (
	MainShouldFail  HttpStatus = -1
	NotHttpExpected HttpStatus = -2
	NoRequestSent   HttpStatus = -3
)

type Constraint int

const (
	Is Constraint = iota
	Contains
)

type FuncBytesTesting func([]byte, []byte) bool

type TestCaseMainType struct {
	name     string
	config   map[string]string
	expected struct {
		status         HttpStatus
		bodyValue      string
		bodyConstraint Constraint
	}
}
type TestCaseHttpDisableSocketReusingType struct {
	name    string
	config  map[string]string
	noReuse bool
}
type TestCaseTcpSocketReusingDisabledType struct {
	name           string
	config         map[string]string
	mainShouldFail bool
}

const (
	unexpectedError                  = "Unexpected Error: %#v"
	testCertHostname                 = "client.badssl.com"
	testCertSuccessPattern           = "body { background: green; }"
	testCertClientCertPem            = "badssl.com-client.crt.pem"
	testCertClientKeyNoEncryptionPem = "badssl.com-client_NOENCRYPTION.key.pem"
)

func TestMainHttp(t *testing.T) {
	mainSupervisor := tests.NewMainSupervisor(t, main)
	defer mainSupervisor.Close()
	exampleDir, err := configurationtest.GetExampleDir(0)
	if err != nil {
		t.Errorf(unexpectedError, err)
		return
	}

	for _, testcase := range []TestCaseMainType{
		{
			name: "Minimal things",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				200,
				testCertSuccessPattern,
				Contains,
			},
		},
		{
			name: "Backend defined with its protocol",
			config: map[string]string{
				"backend":  fmt.Sprintf("https://%s", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Contains,
			},
		},
		{
			name: "Backend defined with its port AND its protocol",
			config: map[string]string{
				"backend":  fmt.Sprintf("https://%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Contains,
			},
		},
		{
			name: "Backend a wrong client cert",
			config: map[string]string{
				"backend":  "client-cert-missing.badssl.com:443",
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				400,
				"No required SSL certificate was sent",
				Contains,
			},
		},
		{
			name: "Non valid backend",
			config: map[string]string{
				"backend":  "0.0.0.0:1111",
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				503,
				"dial tcp 0.0.0.0:1111: connect",
				Contains,
			},
		},
		{
			name: "Non existing backend",
			config: map[string]string{
				"backend":  "0.0.0.0:443",
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				503,
				"dial tcp 0.0.0.0:443: connect",
				Contains,
			},
		},
		{
			name: "Wrong CA for validating the Server",
			config: map[string]string{
				"backend":   fmt.Sprintf("%s:443", testCertHostname),
				"cert":      filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key":  filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":      "http",
				"server-ca": filepath.Join(exampleDir, testCertClientCertPem),
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				503,
				"tls: failed to verify certificate: x509: certificate signed by unknown authority",
				Is,
			},
		},
		{
			name: "Wrong listen definition: Null port",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
				"listen":   "0.0.0.0:0",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong listen definition: Negative port",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
				"listen":   "0.0.0.0:-1",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong listen definition: only the port",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
				"listen":   "443",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong Client Certificate Path",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     fmt.Sprintf("%d", rand.Int()),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong Client Key Path",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": fmt.Sprintf("%d", rand.Int()),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong Mode",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     fmt.Sprintf("%d", rand.Int()),
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
	} {
		t.Logf("Running Test `%s`", testcase.name)

		addr, hasReturned, err := mainSupervisor.Run(testcase.config)
		if err != nil {
			t.Errorf(unexpectedError, err)
			continue
		}

		if testcase.expected.status != MainShouldFail {
			if hasReturned {
				t.Errorf("The main function has returned and should not returned.")
				continue
			}
		} else {
			if !hasReturned {
				t.Errorf("The main function has not returned but should returned.")
			}
			continue
		}

		addr = fmt.Sprintf("http://%s", addr)
		resp, err := http.Get(addr)
		if err != nil {
			t.Errorf(unexpectedError, err)
			continue
		}

		if resp.StatusCode != int(testcase.expected.status) {
			t.Errorf("Wrong Status Code! Had=%d, Expected=%d", resp.StatusCode, testcase.expected.status)
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf(unexpectedError, err)
			continue
		}
		body = bytes.TrimSpace(body)

		testValue := []byte(strings.TrimSpace(testcase.expected.bodyValue))
		var testFunc FuncBytesTesting

		if testcase.expected.bodyConstraint == Is {
			testFunc = bytes.Equal
		} else {
			testFunc = bytes.Contains
		}

		if !testFunc(body, testValue) {
			t.Errorf("The body does not pass via the condition! Condition = `%d`; Condition Value = `%s`; Body = `%s`", testcase.expected.bodyConstraint, testcase.expected.bodyValue, body)
		}
	}
}

func TestMainTcp(t *testing.T) {
	mainSupervisor := tests.NewMainSupervisor(t, main)
	defer mainSupervisor.Close()
	exampleDir, err := configurationtest.GetExampleDir(0)
	if err != nil {
		t.Errorf(unexpectedError, err)
		return
	}

	for _, testcase := range []TestCaseMainType{
		{
			name: "Minimal things",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				200,
				testCertSuccessPattern,
				Contains,
			},
		},
		{
			name: "Backend defined with its protocol",
			config: map[string]string{
				"backend":  fmt.Sprintf("https://%s", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Contains,
			},
		},
		{
			name: "Backend defined with its port AND its protocol",
			config: map[string]string{
				"backend":  fmt.Sprintf("https://%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Contains,
			},
		},
		{
			name: "Backend a wrong client cert",
			config: map[string]string{
				"backend":  "client-cert-missing.badssl.com:443",
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				400,
				"No required SSL certificate was sent",
				Contains,
			},
		},
		{
			name: "Non existing backend",
			config: map[string]string{
				"backend":  "0.0.0.0:443",
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				NoRequestSent,
				"dial tcp 0.0.0.0:443: connect",
				Contains,
			},
		},
		{
			name: "Wrong CA for validating the Server",
			config: map[string]string{
				"backend":   fmt.Sprintf("%s:443", testCertHostname),
				"cert":      filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key":  filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":      "tcp",
				"server-ca": filepath.Join(exampleDir, testCertClientCertPem),
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				NoRequestSent,
				"tls: failed to verify certificate: x509: certificate signed by unknown authority",
				Is,
			},
		},
		{
			name: "Wrong listen definition: Null port",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
				"listen":   "0.0.0.0:0",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong listen definition: Negative port",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:tcp", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
				"listen":   "0.0.0.0:-1",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong listen definition: only the port",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
				"listen":   "443",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong Client Certificate Path",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     fmt.Sprintf("%d", rand.Int()),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong Client Key Path",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": fmt.Sprintf("%d", rand.Int()),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
		{
			name: "Wrong Mode",
			config: map[string]string{
				"backend":  fmt.Sprintf("%s:443", testCertHostname),
				"cert":     filepath.Join(exampleDir, testCertClientCertPem),
				"cert-key": filepath.Join(exampleDir, testCertClientKeyNoEncryptionPem),
				"mode":     fmt.Sprintf("%d", rand.Int()),
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				MainShouldFail,
				"",
				Is,
			},
		},
	} {
		testingFnc := func(testcase TestCaseMainType) {
			t.Logf("Running Test `%s`", testcase.name)

			addr, hasReturned, err := mainSupervisor.Run(testcase.config)
			if err != nil {
				t.Errorf(unexpectedError, err)
				return
			}
			defer mainSupervisor.Close()

			if testcase.expected.status != MainShouldFail {
				if hasReturned {
					t.Errorf("The main function has returned and should not returned.")
					return
				}
			} else {
				if !hasReturned {
					t.Errorf("The main function has not returned but should returned.")
				}
				return
			}

			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Errorf(unexpectedError, err)
				return
			}
			defer conn.Close()

			connReader := bufio.NewReader(conn)

			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			body, err := io.ReadAll(connReader)
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf(unexpectedError, err)
					return
				}
			}

			statusCode := int(NoRequestSent)

			if len(body) == 0 {
				// No error have been raised when opening the socket

				hostname := "example.com"
				if v, has := testcase.config["backend"]; has {
					hostname = v
				}

				req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", hostname), nil)
				if err != nil {
					t.Errorf(unexpectedError, err)
				}
				hostname, _ = strings.CutSuffix(hostname, ":443")
				req.Header.Add("Host", hostname)
				req.Header.Add("Connection", "close")
				req.Header.Add("Content-Length", "0")
				err = req.Write(conn)
				if err != nil {
					t.Errorf(unexpectedError, err)
					return
				}

				conn.SetReadDeadline(time.Time{})
				body, err = io.ReadAll(connReader)
				if err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Errorf(unexpectedError, err)
						return
					}
				}
				statusCode = int(NotHttpExpected)

				// Now, we have the conn content.

				// Let's see if it's a HTTP Response!
				bodyReader := bufio.NewReader(bytes.NewReader(body))

				resp, err := http.ReadResponse(bodyReader, req)
				if err == nil {
					// It's an HTTP response, so, changing the variables we will compare
					statusCode = resp.StatusCode
					defer resp.Body.Close()
					body, err = io.ReadAll(resp.Body)
					if err != nil {
						t.Errorf(unexpectedError, err)
						return
					}
				}
			}

			if statusCode != int(testcase.expected.status) {
				t.Errorf("Wrong Status Code! Had=%d, Expected=%d", statusCode, testcase.expected.status)
			}

			body = bytes.TrimSpace(body)

			testValue := []byte(strings.TrimSpace(testcase.expected.bodyValue))
			var testFunc FuncBytesTesting

			if testcase.expected.bodyConstraint == Is {
				testFunc = bytes.Equal
			} else {
				testFunc = bytes.Contains
			}

			if !testFunc(body, testValue) {
				t.Errorf("The body does not pass via the condition! Condition = `%d`; Condition Value = `%s`; Body = `%s`", testcase.expected.bodyConstraint, testcase.expected.bodyValue, body)
			}
		}
		testingFnc(testcase)
	}
}

// TODO Find a way to test that!
// func TestUnsafeKeyLogPath(t *testing.T) {
// }

func TestHttpDisableSocketReusing(t *testing.T) {
	mainSupervisor := tests.NewMainSupervisor(t, main)
	defer mainSupervisor.Close()

	srv, err := tests.NewStartedTlsServerCounter(true)
	if err != nil {
		t.Errorf(unexpectedError, err)
		return
	}

	for _, testcase := range []TestCaseHttpDisableSocketReusingType{
		{
			name: "No option",
			config: map[string]string{
				"backend":  srv.Backend(),
				"cert":     srv.CertClientFilePath,
				"cert-key": srv.KeyClientFilePath,
				"mode":     srv.Mode(),
			},
			noReuse: false,
		},
		// TODO
		// {
		// 	name: "Option to false",
		// 	config: map[string]string{
		// 		"backend":                srv.Backend(),
		// 		"cert":                   srv.CertClientFilePath,
		// 		"cert-key":               srv.KeyClientFilePath,
		// 		"mode":                   srv.Mode(),
		// 		"disable-socket-reusing": "false",
		// 	},
		// 	noReuse: false,
		// },
		{
			name: "Option to true",
			config: map[string]string{
				"backend":                srv.Backend(),
				"cert":                   srv.CertClientFilePath,
				"cert-key":               srv.KeyClientFilePath,
				"mode":                   srv.Mode(),
				"disable-socket-reusing": "true",
			},
			noReuse: true,
		},
	} {
		t.Logf("Running Test `%s`", testcase.name)

		addr, hasReturned, err := mainSupervisor.Run(testcase.config)
		if err != nil {
			t.Errorf(unexpectedError, err)
		}
		addr = fmt.Sprintf("http://%s", addr)

		if hasReturned {
			t.Errorf("The main function has returned and should not returned.")
			continue
		}

		for i := 0; i < 10; i++ {
			resp, err := http.Get(addr)
			if err != nil {
				t.Errorf(unexpectedError, err)
				continue
			}

			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf(unexpectedError, err)
				continue
			}

			var msg string
			var expected string
			if testcase.noReuse {
				expected = "0"
				msg = "The proxy seems to re-use the socket despite the flag"
			} else {
				expected = fmt.Sprintf("%d", i)
				msg = "The proxy seems to re-use the socket despite the flag"
			}
			if !bytes.Equal(body, []byte(expected)) {
				t.Errorf("%s! Expected: %s; Body: %s", msg, expected, body)
			}
		}
	}
}

func TestTcpIsSocketReusingDisabled(t *testing.T) {
	mainSupervisor := tests.NewMainSupervisor(t, main)
	defer mainSupervisor.Close()

	srv, err := tests.NewStartedTlsServerCounter(false)
	if err != nil {
		t.Errorf(unexpectedError, err)
		return
	}

	for _, testcase := range []TestCaseTcpSocketReusingDisabledType{
		{
			name: "No option",
			config: map[string]string{
				"backend":  srv.Backend(),
				"cert":     srv.CertClientFilePath,
				"cert-key": srv.KeyClientFilePath,
				"mode":     srv.Mode(),
			},
			mainShouldFail: false,
		},
		// TODO
		// {
		// 	name: "Option to false",
		// 	config: map[string]string{
		// 		"backend":                srv.Backend(),
		// 		"cert":                   srv.CertClientFilePath,
		// 		"cert-key":               srv.KeyClientFilePath,
		// 		"mode":                   srv.Mode(),
		// 		"disable-socket-reusing": "false",
		// 	},
		// 	mainShouldFail: true,
		// },
		{
			name: "Option to true",
			config: map[string]string{
				"backend":                srv.Backend(),
				"cert":                   srv.CertClientFilePath,
				"cert-key":               srv.KeyClientFilePath,
				"mode":                   srv.Mode(),
				"disable-socket-reusing": "true",
			},
			mainShouldFail: true,
		},
	} {
		t.Logf("Running Test `%s`", testcase.name)

		addr, hasReturned, err := mainSupervisor.Run(testcase.config)
		if err != nil {
			t.Errorf(unexpectedError, err)
			continue
		}

		if testcase.mainShouldFail {
			if !hasReturned {
				t.Errorf("The main function has not returned but should returned.")
			}
			continue
		}
		if hasReturned {
			t.Errorf("The main function has returned and should not returned.")
			continue
		}

		for i := 0; i < 10; i++ {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Errorf(unexpectedError, err)
				continue
			}
			defer conn.Close()
			byteSent := make([]byte, 2)
			for j := 0; j < 10; j++ {
				conn.Write([]byte("R\n"))

				_, err := conn.Read(byteSent)
				if err != nil {
					t.Errorf(unexpectedError, err)
					continue
				}

				var msg string
				expected := fmt.Sprintf("%d\n", j%10)
				msg = "The proxy seems to re-use the socket despite the TCP mode"
				if !bytes.Equal(byteSent, []byte(expected)) {
					t.Errorf("%s! Expected: %s; Body: %s; Requested number: %d", msg, expected, byteSent, j)
				}
			}
		}
	}
}
