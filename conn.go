package socks

import (
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
)

// conn implement net.conn
type conn struct {
	session quic.Session
	send    quic.SendStream
	receive quic.ReceiveStream

	// must use extra Mutex because SendStream
	// is not safe for use by multiple goroutines
	m sync.Mutex
}

func newConn(session quic.Session) (*conn, error) {
	send, err := session.OpenUniStream()
	if err != nil {
		return nil, err
	}
	return &conn{
		session: session,
		send:    send,
	}, nil
}

// Read reads data from the connection
func (c *conn) Read(b []byte) (n int, err error) {
	if c.receive == nil {
		receive, err := c.session.AcceptUniStream()
		if err != nil {
			return 0, err
		}
		c.receive = receive
	}
	return c.receive.Read(b)
}

// Write writes data to the connection
func (c *conn) Write(b []byte) (n int, err error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.send.Write(b)
}

// Close is used to close connection
func (c *conn) Close() error {
	return c.session.Close()
}

// LocalAddr is used to get local address
func (c *conn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

// RemoteAddr is used to get remote address
func (c *conn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

// SetDeadline is used to set read and write deadline
func (c *conn) SetDeadline(t time.Time) error {
	if c.receive != nil {
		err := c.receive.SetReadDeadline(t)
		if err != nil {
			return err
		}
	}
	return c.send.SetWriteDeadline(t)
}

// SetReadDeadline is used to set read deadline
func (c *conn) SetReadDeadline(t time.Time) error {
	if c.receive != nil {
		return c.receive.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline is used to set write deadline
func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.send.SetWriteDeadline(t)
}
