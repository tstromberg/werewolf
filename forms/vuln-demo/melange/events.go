package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const historySize = 1024

type event struct {
	ID      uint64 `json:"id"`
	Time    string `json:"time"`
	Kind    string `json:"kind"`
	Service string `json:"service"`
	Message string `json:"message"`
}

type journal struct {
	sync.Mutex
	next     uint64
	lastLoss uint64
	rows     []event
	wake     chan struct{}
	out      io.Writer
}

func newJournal(out io.Writer) *journal {
	return &journal{wake: make(chan struct{}), out: out}
}

func (j *journal) add(kind, service, message string) {
	j.Lock()
	defer j.Unlock()
	j.next++
	e := event{j.next, time.Now().UTC().Format(time.RFC3339Nano), kind, service, clip(message, 16<<10)}
	if len(j.rows) == historySize {
		copy(j.rows, j.rows[1:])
		j.rows = j.rows[:historySize-1]
	}
	j.rows = append(j.rows, e)
	if j.out != nil {
		b, _ := json.Marshal(e)
		fmt.Fprintf(j.out, "vuln-console: %s\n", b)
	}
	close(j.wake)
	j.wake = make(chan struct{})
}

func (j *journal) since(id uint64) ([]event, <-chan struct{}) {
	j.Lock()
	defer j.Unlock()
	var rows []event
	for _, e := range j.rows {
		if e.ID > id {
			rows = append(rows, e)
		}
	}
	return rows, j.wake
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + " [truncated]"
}

// kmsg's sequence is independent of the bounded file's offset. It survives a
// wrap even when the file has already grown past its previous size.
func kernelRecords(text string, last *uint64, j *journal) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	for scanner.Scan() {
		header, message, ok := strings.Cut(scanner.Text(), ";")
		if !ok {
			continue
		}
		fields := strings.Split(header, ",")
		if len(fields) < 3 {
			continue
		}
		seq, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		if seq == 0 && strings.HasPrefix(message, "vuln-kmsg:") {
			counter, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				continue
			}
			if counter == 0 {
				counter = 1
			}
			j.Lock()
			fresh := counter > j.lastLoss
			if fresh {
				j.lastLoss = counter
			}
			j.Unlock()
			if fresh {
				j.add("loss", "kernel", message)
			}
			continue
		}
		if seq <= *last {
			continue
		}
		*last = seq
		kind := "kernel"
		if strings.Contains(message, "type=1309") || strings.Contains(message, "type=1327") {
			kind = "exec"
		}
		if strings.Contains(message, "SECCOMP") || strings.Contains(message, "type=1326") || strings.Contains(message, "type=1423") || strings.Contains(message, "landlock") || strings.Contains(message, "success=no") {
			kind = "violation"
		}
		// Keep the authoritative raw audit record and render its hex argv too.
		if _, tail, ok := strings.Cut(message, "proctitle="); ok {
			raw := strings.Fields(tail)
			if len(raw) > 0 {
				if b, err := hex.DecodeString(raw[0]); err == nil {
					message += " argv=" + strconv.Quote(strings.ReplaceAll(string(b), "\x00", " "))
				}
			}
		}
		j.add(kind, "kernel", message)
	}
}

func monitorKernel(path string, j *journal) {
	var last uint64
	missing := false
	for {
		f, err := os.Open(path)
		if err != nil {
			if !missing {
				j.add("error", "kernel", err.Error())
				missing = true
			}
		} else {
			b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
			f.Close()
			if err == nil {
				kernelRecords(string(b), &last, j)
				missing = false
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func monitorSeal(path string, j *journal) {
	counts := make(map[string]string)
	for {
		b, err := os.ReadFile(path)
		if err == nil {
			for line := range strings.SplitSeq(string(b), "\n") {
				f := strings.Fields(line)
				if len(f) == 5 && counts[f[0]] != f[1] {
					counts[f[0]] = f[1]
					j.add("violation", "seal-watch", line)
				}
			}
		}
		time.Sleep(time.Second)
	}
}
