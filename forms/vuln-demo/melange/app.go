package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Run only the manifest's fixed argv, inheriting the application's own leash.
// Every line reaches the console as escaped JSON and, when available, the UI.
func runApp(name string, argv []string) int {
	if len(argv) == 0 {
		return 127
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 127
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 127
	}
	if err := cmd.Start(); err != nil {
		appEvent(name, err.Error())
		return 127
	}
	var readers sync.WaitGroup
	for _, pipe := range []io.Reader{stdout, stderr} {
		readers.Go(func() {
			reader := bufio.NewReaderSize(pipe, 8192)
			for {
				line, _, err := reader.ReadLine()
				if len(line) > 0 {
					appEvent(name, string(line))
				}
				if err != nil {
					return
				}
			}
		})
	}
	readers.Wait()
	err = cmd.Wait()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		return exit.ExitCode()
	}
	return 1
}

func appEvent(name, message string) {
	b, _ := json.Marshal(event{Kind: "app", Service: name, Message: clip(message, 16000)})
	fmt.Fprintf(os.Stdout, "vuln-console: %s\n", b)
	c, err := net.DialTimeout("unixgram", eventSocket, time.Second)
	if err == nil {
		c.SetWriteDeadline(time.Now().Add(time.Second))
		c.Write(b)
		c.Close()
	}
}
