package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestMalformedHTTPIsRecordedBeforeHandler(t *testing.T) {
	j := newJournal(nil)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("malformed HTTP reached handler") }))
	s.Listener = wireListener{s.Listener, "test", j}
	s.Start()
	defer s.Close()
	c, err := net.DialTimeout("tcp", s.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("NOT-HTTP\x00 /invalid\r\n\r\n"))
	response, err := io.ReadAll(c)
	c.Close()
	if err != nil || !strings.Contains(string(response), "400 Bad Request") {
		t.Fatal(string(response), err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, _ := j.since(0)
		if len(rows) > 0 {
			if rows[0].Kind != "wire" || !strings.Contains(rows[0].Message, "NOT-HTTP\x00") {
				t.Fatal(rows)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("malformed bytes not recorded")
		}
		time.Sleep(time.Millisecond)
	}
}

func sshTestAddress(t *testing.T) string {
	t.Helper()
	key, err := hostKey(filepath.Join(t.TempDir(), "host-key"))
	if err != nil {
		t.Fatal(err)
	}
	config := sshConfig(key, "demo")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handleSSHCommands(c, config, func(ctx context.Context, name string, args ...string) *exec.Cmd {
					return exec.CommandContext(ctx, "/usr/bin/"+filepath.Base(name), args...)
				})
			}()
		}
	}()
	return l.Addr().String()
}

func sshTestClient(t *testing.T, address, user, password string) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", address, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 2 * time.Second})
}

func TestSSHAnyPasswordOnlyForDemo(t *testing.T) {
	address := sshTestAddress(t)
	for _, password := range []string{"", "arbitrary password"} {
		c, err := sshTestClient(t, address, "demo", password)
		if err != nil {
			t.Fatal(err)
		}
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Output("/usr/bin/id -u")
		s.Close()
		c.Close()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			t.Fatal(string(out), err)
		}
	}
	c, err := sshTestClient(t, address, "root", "arbitrary password")
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("accepted another username")
	}
}

func TestSSHRefusesShellPTYAndForwarding(t *testing.T) {
	address := sshTestAddress(t)
	for _, request := range []string{"shell", "pty-req", "subsystem"} {
		c, err := sshTestClient(t, address, "demo", "test")
		if err != nil {
			t.Fatal(err)
		}
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		ok, err := s.SendRequest(request, true, nil)
		if err != nil || ok {
			t.Fatal(request, ok, err)
		}
		s.Close()
		c.Close()
	}
	c, err := sshTestClient(t, address, "demo", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	forwarded, err := c.Dial("tcp", "127.0.0.1:80")
	if forwarded != nil {
		forwarded.Close()
	}
	if err == nil {
		t.Fatal("accepted TCP forwarding")
	}
}

func TestSSHCommandsCannotBypassNarrowing(t *testing.T) {
	for _, name := range []string{"/usr/bin/coreutils", "/usr/bin/../bin/cat", "/bin/cat", "/usr/bin/node", "/usr/lib/werewolf/leash"} {
		if _, ok := sshProgram(name); ok {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"cat", "/usr/bin/cat", "id", "/usr/bin/id", "uname"} {
		program, ok := sshProgram(name)
		if !ok || !strings.HasPrefix(program, "/etc/sv/vuln-sshd/narrow/") {
			t.Fatal(name, program)
		}
	}
}
