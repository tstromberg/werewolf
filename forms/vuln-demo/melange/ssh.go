package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshEvent(message string) {
	b, _ := json.Marshal(event{Kind: "ssh", Service: "sshd", Message: clip(message, 16000)})
	fmt.Fprintf(os.Stdout, "vuln-sshd: %s\n", b)
	c, err := net.DialTimeout("unixgram", eventSocket, time.Second)
	if err == nil {
		c.SetWriteDeadline(time.Now().Add(time.Second))
		c.Write(b)
		c.Close()
	}
}

func hostKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(b)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "vuln-demo")
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(pem.EncodeToMemory(block))
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return ssh.NewSignerFromKey(private)
}

func serveSSH(address, keyPath, user string) error {
	key, err := hostKey(keyPath)
	if err != nil {
		return err
	}
	config := &ssh.ServerConfig{MaxAuthTries: 3,
		PasswordCallback: func(c ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			if c.User() != user {
				sshEvent(fmt.Sprintf("auth refused remote=%s user=%q", c.RemoteAddr(), c.User()))
				return nil, errors.New("unknown demo user")
			}
			sshEvent(fmt.Sprintf("auth accepted remote=%s user=%q (any password)", c.RemoteAddr(), c.User()))
			return nil, nil
		},
	}
	config.AddHostKey(key)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	sshEvent("listening " + address + " user=" + user + "; exec only; no shell or forwarding")
	slots := make(chan struct{}, 32)
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() { defer func() { <-slots }(); defer c.Close(); handleSSH(c, config) }()
	}
}

func handleSSH(c net.Conn, config *ssh.ServerConfig) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(c, config)
	if err != nil {
		sshEvent(fmt.Sprintf("handshake remote=%s error=%q", c.RemoteAddr(), err))
		return
	}
	defer conn.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute))
	go func() {
		for r := range requests {
			r.Reply(false, nil)
		}
	}()
	// One command per connection keeps the deliberately permissive login bounded.
	used := false
	for incoming := range channels {
		if incoming.ChannelType() != "session" || used {
			incoming.Reject(ssh.Prohibited, "exec session only")
			continue
		}
		used = true
		channel, reqs, err := incoming.Accept()
		if err != nil {
			return
		}
		go func() { defer channel.Close(); handleSession(conn.RemoteAddr().String(), channel, reqs) }()
	}
}

func handleSession(remote string, channel ssh.Channel, requests <-chan *ssh.Request) {
	for r := range requests {
		if r.Type != "exec" {
			sshEvent(fmt.Sprintf("request refused remote=%s type=%q", remote, r.Type))
			r.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if ssh.Unmarshal(r.Payload, &payload) != nil {
			r.Reply(false, nil)
			return
		}
		sshEvent(fmt.Sprintf("command remote=%s command=%q", remote, payload.Command))
		argv, err := commandArgs(payload.Command)
		if err != nil {
			r.Reply(false, nil)
			io.WriteString(channel.Stderr(), err.Error()+"\n")
			return
		}
		r.Reply(true, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		// Inherit no SSH-controlled environment or stdin. Landlock and pledge
		// enforce the service's executable, file and network policy on the child.
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "LANG=C"}
		output := &boundedOutput{writer: channel, remaining: 64 << 10}
		cmd.Stdout, cmd.Stderr = output, output
		err = cmd.Run()
		status := uint32(0)
		if err != nil {
			status = 126
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() >= 0 {
				status = uint32(exit.ExitCode())
			}
			fmt.Fprintf(channel.Stderr(), "%s\n", err)
		}
		sshEvent(fmt.Sprintf("result remote=%s status=%d command=%q", remote, status, payload.Command))
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

type boundedOutput struct {
	sync.Mutex
	writer    io.Writer
	remaining int
}

func (w *boundedOutput) Write(b []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	n := len(b)
	if len(b) > w.remaining {
		b = b[:w.remaining]
	}
	if len(b) > 0 {
		if _, err := w.writer.Write(b); err != nil {
			return 0, err
		}
		w.remaining -= len(b)
	}
	return n, nil
}

// Parse argv quoting only; shell operators and expansions are never interpreted.
func commandArgs(s string) ([]string, error) {
	if len(s) > 4096 {
		return nil, errors.New("command too long")
	}
	var args []string
	var word strings.Builder
	var quote rune
	escape, started := false, false
	for _, c := range s {
		if c == 0 || c == '\n' || c == '\r' {
			return nil, errors.New("control character")
		}
		if escape {
			word.WriteRune(c)
			escape = false
			started = true
			continue
		}
		if c == '\\' && quote != '\'' {
			escape = true
			started = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			started = true
			continue
		}
		if c == ' ' || c == '\t' {
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		if strings.ContainsRune(";|&<>$`()", c) {
			return nil, errors.New("shell syntax unavailable")
		}
		word.WriteRune(c)
		started = true
	}
	if escape || quote != 0 {
		return nil, errors.New("unfinished quote")
	}
	if started {
		args = append(args, word.String())
	}
	if len(args) == 0 || args[0] == "" {
		return nil, errors.New("empty command")
	}
	return args, nil
}
