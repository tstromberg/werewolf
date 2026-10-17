package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestOnlyBareHTTP10ProbeIsQuiet(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		quiet bool
	}{
		{"GET / HTTP/1.0\r\n\r\n", true},
		{"GET / HTTP/1.0\r\nUser-Agent: scanner\r\n\r\n", false},
		{"GET / HTTP/1.0\r\nHost: demo\r\n\r\n", false},
		{"GET /?x=1 HTTP/1.0\r\n\r\n", false},
		{"GET / HTTP/1.1\r\nHost: demo\r\n\r\n", false},
		{"POST / HTTP/1.0\r\nContent-Length: 1\r\n\r\nx", false},
	} {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(tc.raw)))
		if err != nil {
			t.Fatal(err)
		}
		if got := basicProbe(r); got != tc.quiet {
			t.Errorf("%q quiet=%v", tc.raw, got)
		}
	}
}

func TestProxyPreservesEndpointAndBody(t *testing.T) {
	body := strings.Repeat("payload\x00", 2048)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(b) != body {
			t.Error("forwarded body changed")
		}
		if r.RequestURI != "/solr/%2e%2e/admin//cores?action=%24%7Bjndi%3Adns%3Ax%7D&odd=%ZZ;keep=1" {
			t.Error(r.RequestURI)
		}
		if r.Host != "demo.example:8983" || r.Header.Get("X-Forwarded-Host") != "demo.example:8983" || r.Header.Get("X-Forwarded-Proto") != "http" || r.Header.Get("X-Forwarded-For") != "192.0.2.25" || r.Header.Get("Forwarded") != "" {
			t.Error("untrusted forwarding metadata survived", r.Host, r.Header)
		}
		w.WriteHeader(201)
	}))
	defer backend.Close()
	j := newJournal(nil)
	r := httptest.NewRequest("POST", "/solr/%2e%2e/admin//cores?action=%24%7Bjndi%3Adns%3Ax%7D&odd=%ZZ;keep=1", strings.NewReader(body))
	r.Host = "demo.example:8983"
	r.RemoteAddr = "192.0.2.25:41123"
	r.Header.Set("X-Forwarded-For", "198.51.100.66")
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Forwarded", "for=198.51.100.66")
	w := httptest.NewRecorder()
	requestLog("solr", proxy(backend.URL, j), j).ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	rows, _ := j.since(0)
	if len(rows) != 2 || rows[0].Kind != "request" || !strings.HasSuffix(rows[1].Message, "[truncated]") {
		t.Fatal(rows)
	}
}

func TestKernelSequenceSurvivesBufferWrap(t *testing.T) {
	j := newJournal(nil)
	var seq uint64
	kernelRecords("6,42,9,-;audit: type=1327 proctitle=6964002D7500\n6,43,10,-;audit: type=1300 success=no\n", &seq, j)
	kernelRecords("6,43,10,-;audit: type=1300 success=no\n6,99,99,-;audit: type=1309 argc=1 a0=\"id\"\n", &seq, j)
	rows, _ := j.since(0)
	if len(rows) != 3 || seq != 99 {
		t.Fatal(rows, seq)
	}
	if rows[0].Kind != "exec" || !strings.Contains(rows[0].Message, "id -u") || rows[1].Kind != "violation" {
		t.Fatal(rows)
	}
}

func TestJournalBoundsAndEscapesAttackerText(t *testing.T) {
	var output bytes.Buffer
	j := newJournal(&output)
	for range historySize + 10 {
		j.add("request", "test", "<script>\n\x1b[2J")
	}
	rows, _ := j.since(0)
	if len(rows) != historySize || rows[0].ID != 11 {
		t.Fatal(len(rows), rows[0].ID)
	}
	if bytes.Contains(output.Bytes(), []byte("\x1b")) || bytes.Contains(output.Bytes(), []byte("<script>")) {
		t.Fatal("console contains unescaped attacker text")
	}
	if !bytes.Contains(page, []byte("text.textContent=e.message")) {
		t.Fatal("UI must render logs as text")
	}
}

func TestSSHArgvDoesNotInterpretShellSyntax(t *testing.T) {
	for _, command := range []string{"id; uname", "id && uname", "cat /etc/shadow | head", "echo $(id)", "echo >x", "id\n", "echo 'unfinished"} {
		if _, err := commandArgs(command); err == nil {
			t.Errorf("accepted %q", command)
		}
	}
	argv, err := commandArgs("/usr/bin/echo 'hello world' \"$HOME\" ''")
	if err != nil || len(argv) != 4 || argv[1] != "hello world" || argv[2] != "$HOME" || argv[3] != "" {
		t.Fatal(argv, err)
	}
}

func TestSSHHostIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-key")
	a, err := hostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PublicKey().Marshal(), b.PublicKey().Marshal()) {
		t.Fatal("host identity changed")
	}
}

func TestRuntimeDenialsAreVisibleAsViolations(t *testing.T) {
	for _, message := range []string{`{"event":"runtime-denial","runtime":"node","group":"exec"}`, `java: {"event":"runtime-denial","group":"native"}`} {
		if appEventKind(message) != "violation" {
			t.Fatal(message)
		}
	}
	if appEventKind(`not JSON runtime-denial`) != "app" {
		t.Fatal("misclassified application text")
	}
	j := newJournal(nil)
	var seq uint64
	kernelRecords("6,42,9,-;audit: type=1423 blockers=fs.write_file path=\"/etc/x\"\n", &seq, j)
	rows, _ := j.since(0)
	if len(rows) != 1 || rows[0].Kind != "violation" {
		t.Fatal(rows)
	}
}

func TestKernelOverrunsDoNotReplayOnEveryPoll(t *testing.T) {
	j := newJournal(nil)
	var seq uint64
	marker := "0,0,1,-;vuln-kmsg: kernel log overrun; records lost\n"
	kernelRecords(marker+"6,100,9,-;next record\n", &seq, j)
	kernelRecords(marker+"6,100,9,-;next record\n", &seq, j)
	kernelRecords("0,0,2,-;vuln-kmsg: kernel log overrun; records lost\n", &seq, j)
	rows, _ := j.since(0)
	if len(rows) != 3 || rows[0].Kind != "loss" || rows[2].Kind != "loss" {
		t.Fatal(rows)
	}
}

func TestServiceCannotImpersonateKernelRecords(t *testing.T) {
	j := newJournal(nil)
	recordServiceEvent(j, event{Kind: "app", Service: "kernel", Message: `{"event":"runtime-denial"}`})
	recordServiceEvent(j, event{Kind: "exec", Service: "kernel", Message: "forged exec"})
	var seq uint64
	kernelRecords("6,42,9,-;audit: type=1309 argc=1 a0=\"id\"\n", &seq, j)
	rows, _ := j.since(0)
	if len(rows) != 2 || rows[0].Service == "kernel" || rows[0].Kind != "violation" || rows[1].Service != "kernel" || rows[1].Kind != "exec" {
		t.Fatal(rows)
	}
}

func TestDashboardOnlyAllowsItsPackagedScriptAndStyle(t *testing.T) {
	w := httptest.NewRecorder()
	dashboard(newJournal(nil)).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	policy := w.Header().Get("Content-Security-Policy")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(policy, "default-src 'none'") || strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "unsafe-eval") {
		t.Fatal(w.Code, w.Header())
	}
	for _, tag := range []string{"script", "style"} {
		blocks := regexp.MustCompile(`(?s)<`+tag+`>(.*?)</`+tag+`>`).FindAllSubmatch(w.Body.Bytes(), -1)
		if len(blocks) != 1 {
			t.Fatalf("expected one packaged %s block", tag)
		}
		digest := sha256.Sum256(blocks[0][1])
		if !strings.Contains(policy, tag+"-src 'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'") {
			t.Fatalf("packaged %s would be blocked", tag)
		}
	}
	if bytes.Contains(w.Body.Bytes(), []byte(" style=")) {
		t.Fatal("inline style attributes are blocked by the dashboard policy")
	}
	attacker := sha256.Sum256([]byte("alert(document.cookie)"))
	if strings.Contains(policy, base64.StdEncoding.EncodeToString(attacker[:])) {
		t.Fatal("unpackaged script allowed")
	}
}
