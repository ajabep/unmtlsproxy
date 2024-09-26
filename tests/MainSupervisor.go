package tests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ajabep/unmtlsproxy/internal/configuration/configurationtest"
)

type MainFunc func()

type MainSupervisor struct {
	envName  string
	testName string
	main     MainFunc
	cmd      *exec.Cmd
}

// Will init a new supervisor to execute the main function without crashing the current program.
// It HAVE to be called in at the very start of the test!
func NewMainSupervisor(t *testing.T, main MainFunc) *MainSupervisor {
	supervisor := &MainSupervisor{
		envName:  "TESTING_EXEC_MAIN" + t.Name(),
		testName: t.Name(),
		main:     main,
	}
	if encArgs, has := os.LookupEnv(supervisor.envName); has {
		jsonArgs, err := base64.RawStdEncoding.DecodeString(encArgs)
		if err != nil {
			panic(err)
		}

		var config map[string]string
		err = json.Unmarshal(jsonArgs, &config)
		if err != nil {
			panic(err)
		}

		configurationtest.SetupConfigurationEnv(config)
		supervisor.main()
		os.Exit(255) // Should never happen, but, just in case of
	}
	return supervisor
}

func (m *MainSupervisor) Run(config map[string]string) (string, bool, error) {
	var err error
	if m.cmd != nil {
		m.Close()
	}

	addr, has := config["listen"]
	if !has {
		addr, _, _, err = configurationtest.NewListener()
		if err != nil {
			return "", false, err
		}
		config["listen"] = addr
	}

	mainStarted := make(chan struct{}, 1)
	mainStopped := make(chan struct{}, 2)

	go func(config map[string]string, mainStarted, mainStopped chan<- struct{}) {
		jsonArgs, err := json.Marshal(config)
		if err != nil {
			panic(err)
		}
		rawArgs := base64.RawStdEncoding.EncodeToString(jsonArgs)

		m.cmd = exec.Command(os.Args[0], fmt.Sprintf("-test.run=%s", m.testName))
		m.cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", m.envName, rawArgs))

		close(mainStarted)
		_ = m.cmd.Run()
		close(mainStopped)
	}(config, mainStarted, mainStopped)

	<-mainStarted
	mainHasReturned := false
	select {
	case <-mainStopped:
		mainHasReturned = true
	case <-time.After(500 * time.Millisecond):
	}

	return addr, mainHasReturned, nil
}
func (m *MainSupervisor) Close() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_, _ = m.cmd.Process.Wait()
	}
	m.cmd = nil
}
