// A static Linux server; the VM never needs the Go compiler.
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			switch r.URL.Path {
			case "/":
				fmt.Fprintln(w, "Hello from Go on werewolf!")
			case "/health":
				fmt.Fprintln(w, "ok")
			default:
				http.NotFound(w, r)
			}
		}),
	}
	log.Print("app: listening on :8080")
	log.Fatal(server.ListenAndServe())
}
