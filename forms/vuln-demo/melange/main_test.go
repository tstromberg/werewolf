package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		if r.RequestURI != "/solr/admin/cores?action=%24%7Bjndi%3Adns%3Ax%7D" {
			t.Error(r.RequestURI)
		}
		w.WriteHeader(201)
	}))
	defer backend.Close()
	j := newJournal(nil)
	r := httptest.NewRequest("POST", "/solr/admin/cores?action=%24%7Bjndi%3Adns%3Ax%7D", strings.NewReader(body))
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
