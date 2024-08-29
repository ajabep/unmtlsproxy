package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajabep/unmtlsproxy/internal/configuration/configurationtest"
	"github.com/ajabep/unmtlsproxy/tests"
)

type HttpStatus int

const (
	MainShouldFail HttpStatus = -1
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

func TestMainHttp(t *testing.T) {
	mainSupervisor := tests.NewMainSupervisor(t, main)
	defer mainSupervisor.Close()
	exampleDir, err := configurationtest.GetExampleDir(0)
	if err != nil {
		panic(err)
	}

	for _, testcase := range []TestCaseMainType{
		{
			name: "Minimal things",
			config: map[string]string{
				"backend":  "https://client.badssl.com",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				200,
				"body { background: green; }",
				Contains,
			},
		},
		// TODO: Open this notation in HTTP mode
		//{
		//	name: "Backend defined with its port",
		//	config: map[string]string{
		//		"backend":  "client.badssl.com:443",
		//		"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
		//		"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
		//		"mode":     "http",
		//	},
		//	expected: struct {
		//		status         HttpStatus
		//		bodyValue      string
		//		bodyConstraint Constraint
		//	}{
		//		200,
		//		"body { background: green; }",
		//		Contains,
		//	},
		//},
		{
			name: "Backend defined with its port AND its protocol",
			config: map[string]string{
				"backend":  "https://client.badssl.com:443",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				200,
				"body { background: green; }",
				Contains,
			},
		},
		{
			name: "Backend a wrong client cert",
			config: map[string]string{
				"backend":  "https://client-cert-missing.badssl.com",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
		// TODO: Open this notation in HTTP mode
		// {
		// 	name: "Non valid backend",
		// 	config: map[string]string{
		// 		"backend":  "0.0.0.0:1111",
		// 		"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
		// 		"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
		// 		"mode":     "http",
		// 	},
		// 	expected: struct {
		// 		status         HttpStatus
		// 		bodyValue      string
		// 		bodyConstraint Constraint
		// 	}{
		// 		503,
		// 		"dial tcp 0.0.0.0:443: connectex: No connection could be made because the target machine actively refused it.",
		// 		Is,
		// 	},
		// },
		{
			name: "Non existing backend",
			config: map[string]string{
				"backend":  "https://0.0.0.0",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
				"mode":     "http",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				503,
				"dial tcp 0.0.0.0:443: connectex: No connection could be made because the target machine actively refused it.",
				Is,
			},
		},
		{
			name: "Wrong CA for validating the Server",
			config: map[string]string{
				"backend":   "https://client.badssl.com",
				"cert":      filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key":  filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
				"mode":      "http",
				"server-ca": filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
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
				"backend":  "https://client.badssl.com",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "https://client.badssl.com",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "https://client.badssl.com",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "https://client.badssl.com",
				"cert":     fmt.Sprintf("%d", rand.Int()),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "https://client.badssl.com",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
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
			name: "Good Client Key Password",
			config: map[string]string{
				"backend":       "https://client.badssl.com",
				"cert":          filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key":      filepath.Join(exampleDir, "badssl.com-client.key.pem"),
				"cert-key-pass": "badssl.com",
				"mode":          "http",
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
			name: "Wrong Client Key Password",
			config: map[string]string{
				"backend":       "https://client.badssl.com",
				"cert":          filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key":      filepath.Join(exampleDir, "badssl.com-client.key.pem"),
				"cert-key-pass": fmt.Sprintf("%d", rand.Int()),
				"mode":          "http",
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
				"backend":  "https://client.badssl.com",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
			panic(err)
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
			panic(err)
		}

		if resp.StatusCode != int(testcase.expected.status) {
			t.Errorf("Wrong Status Code! Had=%d, Expected=%d", resp.StatusCode, testcase.expected.status)
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
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
		panic(err)
	}

	for _, testcase := range []TestCaseMainType{
		{
			name: "Minimal things",
			config: map[string]string{
				"backend":  "client.badssl.com:433",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				200,
				"body { background: green; }",
				Contains,
			},
		},
		{
			name: "Backend defined with its protocol",
			config: map[string]string{
				"backend":  "https://client.badssl.com:443",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "https://client.badssl.com:443",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
				"mode":     "tcp",
			},
			expected: struct {
				status         HttpStatus
				bodyValue      string
				bodyConstraint Constraint
			}{
				503,
				"dial tcp 0.0.0.0:443: connectex: No connection could be made because the target machine actively refused it.",
				Is,
			},
		},
		{
			name: "Wrong CA for validating the Server",
			config: map[string]string{
				"backend":   "client.badssl.com:443",
				"cert":      filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key":  filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
				"mode":      "tcp",
				"server-ca": filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
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
				"backend":  "client.badssl.com:443",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "client.badssl.com:tcp",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "client.badssl.com:443",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "client.badssl.com:443",
				"cert":     fmt.Sprintf("%d", rand.Int()),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
				"backend":  "client.badssl.com:443",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
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
			name: "Good Client Key Password",
			config: map[string]string{
				"backend":       "client.badssl.com:443",
				"cert":          filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key":      filepath.Join(exampleDir, "badssl.com-client.key.pem"),
				"cert-key-pass": "badssl.com",
				"mode":          "tcp",
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
			name: "Wrong Client Key Password",
			config: map[string]string{
				"backend":       "client.badssl.com:443",
				"cert":          filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key":      filepath.Join(exampleDir, "badssl.com-client.key.pem"),
				"cert-key-pass": fmt.Sprintf("%d", rand.Int()),
				"mode":          "tcp",
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
				"backend":  "client.badssl.com:443",
				"cert":     filepath.Join(exampleDir, "badssl.com-client.crt.pem"),
				"cert-key": filepath.Join(exampleDir, "badssl.com-client_NOENCRYPTION.key.pem"),
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
			panic(err)
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

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			panic(err)
		}

		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			panic(err)
		}
		hostname := "example.com"
		if v, has := testcase.config["backend"]; has {
			hostname = v
		}
		req.Header.Add("Host", hostname)
		req.Header.Add("Connection", "close")
		err = req.Write(conn)
		if err != nil {
			panic(err)
		}

		connReader := bufio.NewReader(conn)

		resp, err := http.ReadResponse(connReader, req)
		if err != nil {
			panic(err)
		}

		if resp.StatusCode != int(testcase.expected.status) {
			t.Errorf("Wrong Status Code! Had=%d, Expected=%d", resp.StatusCode, testcase.expected.status)
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
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

//func TestUnsecureKeyLogPath(t *testing.T) {
// TODO
//}

func TestHttpDisableSocketReusing(t *testing.T) {
	mainSupervisor := tests.NewMainSupervisor(t, main)
	defer mainSupervisor.Close()

	srv, err := tests.NewStartedTlsServerCounter(true)
	if err != nil {
		panic(err)
	}

	for _, testcase := range []TestCaseHttpDisableSocketReusingType{
		{
			name: "No options",
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
			panic(err)
		}
		addr = fmt.Sprintf("http://%s", addr)

		if hasReturned {
			t.Errorf("The main function has returned and should not returned.")
			continue
		}

		for i := 0; i < 10; i++ {
			resp, err := http.Get(addr)
			if err != nil {
				panic(err)
			}

			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				panic(err)
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
		panic(err)
	}

	for _, testcase := range []TestCaseTcpSocketReusingDisabledType{
		{
			name: "No options",
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
			panic(err)
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
				panic(err)
			}
			defer conn.Close()
			byteSent := make([]byte, 2)
			for j := 0; j < 10; j++ {
				conn.Write([]byte("R\n"))

				_, err := conn.Read(byteSent)
				if err != nil {
					panic(err)
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

// Not allow HTTP (no SSL) backend in the HTTPS mode! It's completely silly!
// TODO Same for tcp!
