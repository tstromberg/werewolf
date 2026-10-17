package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed page.html
var page []byte

var pageCSP = dashboardPolicy(page)

const eventSocket = "/run/svc/vuln-console/events.sock"

type target struct{ name, public, backend string }

var targets = []target{
	{"Solr", ":8983", "http://127.0.0.1:18983"},
	{"n8n", ":5678", "http://127.0.0.1:15678"},
	{"Langflow", ":7860", "http://127.0.0.1:17860"},
}

func main() {
	mode := flag.String("mode", "web", "web or ssh")
	address := flag.String("listen", ":8080", "dashboard or SSH address")
	key := flag.String("host-key", "/data/svc/vuln-sshd/host-key", "SSH host key")
	user := flag.String("user", "demo", "SSH account accepting any password")
	service := flag.String("service", "app", "application log label")
	flag.Parse()
	log.SetPrefix("vuln-console: ")
	log.SetFlags(0)
	if *mode == "app" {
		os.Exit(runApp(*service, flag.Args()))
	}
	if *mode == "ssh" {
		log.Fatal(serveSSH(*address, *key, *user))
		return
	}
	if *mode != "web" {
		log.Fatal("unknown mode")
	}
	j := newJournal(os.Stdout)
	go monitorKernel("/run/werewolf/vuln-kmsg", j)
	go monitorSeal("/run/werewolf/seal/refused", j)
	go receiveEvents(eventSocket, j)
	for _, t := range targets {
		go func() { log.Fatal(serveHTTP(t.public, requestLog(t.name, proxy(t.backend, j), j), false, t.name, j)) }()
	}
	j.add("start", "dashboard", "HTTP :8080; Solr :8983; n8n :5678; Langflow :7860; SSH demo :22")
	log.Fatal(serveHTTP(*address, requestLog("dashboard", dashboard(j), j), true, "dashboard", j))
}

func dashboard(j *journal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", pageCSP)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(page)
		case "/events":
			streamEvents(w, r, j)
		case "/events.json":
			w.Header().Set("Content-Type", "application/json")
			rows, _ := j.since(0)
			if rows == nil {
				rows = []event{}
			}
			json.NewEncoder(w).Encode(rows)
		default:
			http.NotFound(w, r)
		}
	})
}

func dashboardPolicy(html []byte) string {
	policy := "default-src 'none'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
	for _, tag := range []string{"script", "style"} {
		_, rest, ok := bytes.Cut(html, []byte("<"+tag+">"))
		if !ok {
			continue
		}
		body, _, ok := bytes.Cut(rest, []byte("</"+tag+">"))
		if !ok {
			continue
		}
		digest := sha256.Sum256(body)
		policy += "; " + tag + "-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
	}
	return policy
}

func serveHTTP(address string, handler http.Handler, streaming bool, name string, j *journal) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	timeout := 30 * time.Second
	if streaming {
		timeout = 0
	}
	return (&http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: timeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}).Serve(wireListener{listener, name, j})
}

func basicProbe(r *http.Request) bool {
	return r.Method == "GET" && r.RequestURI == "/" && r.Proto == "HTTP/1.0" && r.Host == "" && len(r.Header) == 0 && r.ContentLength == 0 && len(r.TransferEncoding) == 0
}

func requestLog(name string, next http.Handler, j *journal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !basicProbe(r) {
			var headers bytes.Buffer
			fmt.Fprintf(&headers, "%s %s %s\nHost: %s\n", r.Method, r.RequestURI, r.Proto, r.Host)
			r.Header.Write(&headers)
			j.add("request", name, r.RemoteAddr+" "+headers.String())
			if r.Body != nil && r.Body != http.NoBody {
				// Log a bounded prefix before forwarding, preserving every byte and
				// the original URL, including encoded traversal paths.
				prefix, err := io.ReadAll(io.LimitReader(r.Body, 8193))
				j.add("body", name, r.RemoteAddr+" "+clip(string(prefix), 8192))
				if err != nil {
					http.Error(w, "request body", http.StatusBadRequest)
					return
				}
				r.Body = &prefixBody{Reader: io.MultiReader(bytes.NewReader(prefix), r.Body), Closer: r.Body}
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

type prefixBody struct {
	io.Reader
	io.Closer
}

func proxy(backend string, j *journal) http.Handler {
	u, err := url.Parse(backend)
	if err != nil {
		panic(err)
	}
	p := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(u)
		r.Out.Host = r.In.Host
		// The listener selects the backend; query text is never interpreted
		// here. Preserve even malformed query parameters as received.
		r.Out.URL.RawQuery = r.In.URL.RawQuery
		r.SetXForwarded()
	}}
	p.Transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout: 20 * time.Second, MaxIdleConnsPerHost: 8}
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		j.add("error", backend, err.Error())
		http.Error(w, "application unavailable", http.StatusBadGateway)
	}
	return p
}

func streamEvents(w http.ResponseWriter, r *http.Request, j *journal) {
	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "stream unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	id, _ := strconv.ParseUint(r.Header.Get("Last-Event-ID"), 10, 64)
	// Restarted servers have a fresh event sequence.
	j.Lock()
	if id > j.next {
		id = 0
	}
	j.Unlock()
	controller := http.NewResponseController(w)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		rows, wake := j.since(id)
		controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
		for _, e := range rows {
			b, _ := json.Marshal(e)
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.ID, b); err != nil {
				return
			}
			id = e.ID
		}
		if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
			return
		}
		if err := controller.Flush(); err != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-wake:
		case <-ticker.C:
		}
	}
}

func receiveEvents(path string, j *journal) {
	os.Remove(path) // a socket left by this service's previous run
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		j.add("error", "ssh", err.Error())
		return
	}
	defer c.Close()
	if err := os.Chmod(path, 0660); err != nil {
		j.add("error", "ssh", err.Error())
		return
	}
	buffer := make([]byte, 32<<10)
	for {
		n, _, err := c.ReadFromUnix(buffer)
		if err != nil {
			return
		}
		var e event
		if json.Unmarshal(buffer[:n], &e) == nil {
			recordServiceEvent(j, e)
		}
	}
}

func recordServiceEvent(j *journal, e event) {
	if e.Kind != "ssh" && e.Kind != "app" {
		return
	}
	kind := e.Kind
	if kind == "app" {
		kind = appEventKind(e.Message)
	}
	// A compromised service controls its payload, including its label. Keep
	// that namespace distinct from records read from the protected kernel log.
	j.add(kind, "service/"+clip(e.Service, 56), strings.TrimSpace(e.Message))
}

func appEventKind(message string) string {
	var record struct {
		Event string `json:"event"`
	}
	if at := strings.IndexByte(message, '{'); at >= 0 && json.Unmarshal([]byte(message[at:]), &record) == nil && record.Event == "runtime-denial" {
		return "violation"
	}
	return "app"
}
