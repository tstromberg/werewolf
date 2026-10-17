//go:build integration

package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Clients stay on the host: the shipping image gains no test services or tools.
func TestAppliance(t *testing.T) {
	dashboardURL := os.Getenv("VULN_DEMO_TEST_URL")
	if dashboardURL == "" {
		t.Skip("set VULN_DEMO_TEST_URL for a local appliance boot")
	}
	urls := map[string]string{"dashboard": dashboardURL, "solr": os.Getenv("VULN_DEMO_TEST_SOLR"), "n8n": os.Getenv("VULN_DEMO_TEST_N8N"), "langflow": os.Getenv("VULN_DEMO_TEST_LANGFLOW")}
	for name, address := range urls {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
			t.Fatalf("%s needs an explicit loopback HTTP URL", name)
		}
	}
	sshAddress := os.Getenv("VULN_DEMO_TEST_SSH")
	host, _, err := net.SplitHostPort(sshAddress)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("VULN_DEMO_TEST_SSH needs loopback host:port")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	get := func(address string, headers map[string]string) (int, string, error) {
		req, err := http.NewRequest("GET", address, nil)
		if err != nil {
			return 0, "", err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		response, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		return response.StatusCode, string(body), err
	}
	for _, p := range []struct{ name, path, match string }{{"dashboard", "/", "vuln-demo"}, {"solr", "/solr/admin/info/system?wt=json", "8.11.0"}, {"n8n", "/healthz/readiness", "ok"}, {"langflow", "/health_check", "ok"}} {
		if !t.Run(p.name, func(t *testing.T) {
			deadline := time.Now().Add(180 * time.Second)
			for {
				status, body, err := get(urls[p.name]+p.path, nil)
				if err == nil && status == 200 && strings.Contains(body, p.match) {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("endpoint not ready: status %d, error %v", status, err)
				}
				time.Sleep(time.Second)
			}
		}) {
			return
		}
	}
	if t.Failed() {
		return
	}
	dial := func(user, password string) (*ssh.Client, error) {
		return ssh.Dial("tcp", sshAddress, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	}
	command := func(password, argv string) ([]byte, error) {
		c, err := dial("demo", password)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		s, err := c.NewSession()
		if err != nil {
			return nil, err
		}
		defer s.Close()
		return s.CombinedOutput(argv)
	}
	for _, password := range []string{"werewolf-check-one", "werewolf-check-two"} {
		output, err := command(password, "id")
		if err != nil || !strings.Contains(string(output), "uid=") {
			t.Fatalf("demo password login/direct id failed: %v", err)
		}
	}
	t.Log("two arbitrary passwords and direct id passed")
	if c, err := dial("root", "werewolf-check-one"); err == nil {
		c.Close()
		t.Fatal("SSH admitted root")
	}
	output, err := command("werewolf-check-one", "uname -s")
	if err != nil || strings.TrimSpace(string(output)) != "Linux" {
		t.Fatalf("direct uname failed: %v", err)
	}
	if _, err := command("werewolf-check-one", "sh -c id"); err == nil {
		t.Fatal("SSH admitted a shell command")
	}
	output, err = command("werewolf-check-one", "cat /data/svc/vuln-sshd/host-key")
	if err == nil || strings.Contains(string(output), "PRIVATE KEY") {
		t.Fatal("SSH command could read the private host key")
	}
	c, err := dial("demo", "werewolf-check-one")
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestPty("xterm", 24, 80, nil); err == nil {
		t.Fatal("SSH admitted a PTY")
	}
	if err := s.Shell(); err == nil {
		t.Fatal("SSH admitted an interactive shell")
	}
	s.Close()
	c.Close()
	c, err = dial("demo", "werewolf-check-one")
	if err != nil {
		t.Fatal(err)
	}
	if forwarded, err := c.Dial("tcp", "127.0.0.1:8080"); err == nil {
		forwarded.Close()
		t.Fatal("SSH admitted TCP forwarding")
	}
	c.Close()
	t.Log("root, shell, PTY, forwarding and private-key reads refused")
	marker := fmt.Sprintf("appliance-%d", time.Now().UnixNano())
	if status, _, err := get(urls["solr"]+"/solr/", map[string]string{"X-Demo-Check": marker}); err != nil || status >= 500 {
		t.Fatalf("logged request failed: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, body, err := get(dashboardURL+"/events.json", nil)
		if err == nil && strings.Contains(body, marker) && strings.Contains(body, `"kind":"exec"`) && strings.Contains(body, `"kind":"violation"`) && strings.Contains(body, `"kind":"ssh"`) {
			if strings.Contains(body, "werewolf-check-one") || strings.Contains(body, "werewolf-check-two") {
				t.Fatal("SSH password leaked into journal")
			}
			t.Log("request, exec, SSH and violation records visible")
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("journal missing request/exec/SSH/violation records")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
