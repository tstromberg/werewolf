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
	config := sshConfig(key, "root")
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

func TestSSHAnyPasswordOnlyForRoot(t *testing.T) {
	address := sshTestAddress(t)
	for _, password := range []string{"", "arbitrary password"} {
		c, err := sshTestClient(t, address, "root", password)
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
	c, err := sshTestClient(t, address, "demo", "arbitrary password")
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("accepted another username")
	}
}

func TestOfferedPublicKeyIsRecordedAndRefused(t *testing.T) {
	signer, err := hostKey(filepath.Join(t.TempDir(), "client-key"))
	if err != nil {
		t.Fatal(err)
	}
	metadata := testConnMetadata{
		user: "root", remote: "192.0.2.10:2222", local: "192.0.2.20:22",
		client: "SSH-2.0-test-client", server: "SSH-2.0-test-server", session: []byte{0xde, 0xad},
	}
	line := offeredPublicKey(metadata, signer.PublicKey())
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if !strings.Contains(line, `SSH_USER="root"`) || !strings.Contains(line, `SSH_KEY_ALGORITHM="ssh-ed25519"`) ||
		!strings.Contains(line, `SSH_REMOTE="192.0.2.10:2222"`) || !strings.Contains(line, `SSH_LOCAL="192.0.2.20:22"`) ||
		!strings.Contains(line, `SSH_CLIENT="SSH-2.0-test-client"`) || !strings.Contains(line, `SSH_SERVER="SSH-2.0-test-server"`) ||
		!strings.Contains(line, "SSH_SESSION=dead") || !strings.Contains(line, ssh.FingerprintSHA256(signer.PublicKey())) ||
		!strings.Contains(line, authorized) {
		t.Fatal(line)
	}
	address := sshTestAddress(t)
	c, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 2 * time.Second})
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("accepted public key authentication")
	}
}

type testConnMetadata struct {
	user, remote, local, client, server string
	session                             []byte
}

func (m testConnMetadata) User() string          { return m.user }
func (m testConnMetadata) SessionID() []byte     { return m.session }
func (m testConnMetadata) ClientVersion() []byte { return []byte(m.client) }
func (m testConnMetadata) ServerVersion() []byte { return []byte(m.server) }
func (m testConnMetadata) RemoteAddr() net.Addr  { return testAddr(m.remote) }
func (m testConnMetadata) LocalAddr() net.Addr   { return testAddr(m.local) }

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

func TestSSHRefusesShellPTYAndForwarding(t *testing.T) {
	address := sshTestAddress(t)
	for _, request := range []string{"shell", "pty-req", "subsystem"} {
		c, err := sshTestClient(t, address, "root", "test")
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
	c, err := sshTestClient(t, address, "root", "test")
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
