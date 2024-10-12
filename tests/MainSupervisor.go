package tests

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
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
	cancel   atomic.Value
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

// Run the main function in background, and return if it returns in the X first milliseconds.
func (m *MainSupervisor) Run(config map[string]string) (string, bool, error) {
	var err error

	addr, has := config["listen"]
	if !has {
		addr, _, _, err = configurationtest.NewListener()
		if err != nil {
			return "", false, err
		}
		config["listen"] = addr
	}

	mainStopped := make(chan struct{})

	jsonArgs, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}
	rawArgs := base64.RawStdEncoding.EncodeToString(jsonArgs)

	ctx, cancel := context.WithCancel(context.Background())
	m.ReplaceCancel(cancel)

	go func() {
		m.cmd = exec.CommandContext(ctx, os.Args[0], fmt.Sprintf("-test.run=%s", m.testName))
		m.cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", m.envName, rawArgs))

		m.cmd.Run()
		close(mainStopped)
	}()

	mainHasReturned := false
	select {
	case <-mainStopped:
		mainHasReturned = true
	case <-time.After(500 * time.Millisecond):
	}

	return addr, mainHasReturned, nil
}

// Cancel the current main run
func (m *MainSupervisor) Close() {
	m.ReplaceCancel(nil)
}

// Cancel the current main run, if any, and set {cancel} instead
func (m *MainSupervisor) ReplaceCancel(cancel context.CancelFunc) {
	old_cancel := m.cancel.Swap(cancel)
	if old_cancel != nil {
		old_cancel_typed := old_cancel.(context.CancelFunc)
		if old_cancel_typed != nil {
			old_cancel_typed()
		}
	}
}
