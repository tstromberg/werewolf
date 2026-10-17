package main

import (
	"bytes"
	"net"
	"sync"
)

// Retain a bounded wire prefix: net/http rejects malformed headers and request
// lines before invoking the handler. Valid keepalive requests have individual
// structured records as well. Wire evidence is emitted on connection close.
type wireListener struct {
	net.Listener
	name string
	j    *journal
}

func (l wireListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &wireConn{Conn: c, name: l.name, j: l.j}, nil
}

type wireConn struct {
	net.Conn
	sync.Mutex
	once      sync.Once
	name      string
	j         *journal
	prefix    []byte
	truncated bool
}

func (c *wireConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.Lock()
	keep := min(n, 8192-len(c.prefix))
	c.prefix = append(c.prefix, b[:keep]...)
	c.truncated = c.truncated || keep < n
	c.Unlock()
	return n, err
}
func (c *wireConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.Lock()
		defer c.Unlock()
		if len(c.prefix) == 0 || bytes.Equal(c.prefix, []byte("GET / HTTP/1.0\r\n\r\n")) || bytes.Equal(c.prefix, []byte("GET / HTTP/1.0\n\n")) {
			return
		}
		message := c.RemoteAddr().String() + " " + string(c.prefix)
		if c.truncated {
			message += " [truncated]"
		}
		c.j.add("wire", c.name, message)
	})
	return err
}
