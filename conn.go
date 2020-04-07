package socks

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
)

// ErrConnClosed is an error about closed
var ErrConnClosed = errors.New("connection closed")

// Conn implement net.Conn
type Conn struct {
	// must close rawConn manually to prevent goroutine leak
	// in package github.com/lucas-clemente/quic-go
	// go m.listen() in newPacketHandlerMap()
	rawConn net.PacketConn

	session quic.Session
	stream  quic.Stream

	// must use extra Mutex because SendStream
	// is not safe for use by multiple goroutines
	//
	// stream.Close() must not be called concurrently with Write()
	sendMutex sync.Mutex

	// only server connection need it
	timeout    time.Duration
	acceptErr  error
	acceptOnce sync.Once
}

func (c *Conn) acceptStream() error {
	c.acceptOnce.Do(func() {
		if c.stream == nil {
			c.stream, c.acceptErr = c.session.AcceptStream()
			if c.acceptErr != nil {
				return
			}
			// read data for prevent block
			_ = c.stream.SetReadDeadline(time.Now().Add(c.timeout))
			_, c.acceptErr = c.stream.Read(make([]byte, 1))
		}
	})
	return c.acceptErr
}

// Read reads data from the connection
func (c *Conn) Read(b []byte) (n int, err error) {
	err = c.acceptStream()
	if err != nil {
		return
	}
	return c.stream.Read(b)
}

// Write writes data to the connection
func (c *Conn) Write(b []byte) (n int, err error) {
	err = c.acceptStream()
	if err != nil {
		return
	}
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	return c.stream.Write(b)
}

// Close is used to close connection
func (c *Conn) Close() error {
	c.acceptOnce.Do(func() {
		c.acceptErr = ErrConnClosed
	})
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	if c.stream != nil {
		_ = c.stream.Close()
	}
	err := c.session.CloseWithError(0, "no error")
	if c.rawConn != nil {
		_ = c.rawConn.Close()
	}
	return err
}

// LocalAddr is used to get local address
func (c *Conn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

// RemoteAddr is used to get remote address
func (c *Conn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

// SetDeadline is used to set read and write deadline
func (c *Conn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline is used to set read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	err := c.acceptStream()
	if err != nil {
		return err
	}
	return c.stream.SetReadDeadline(t)
}

// SetWriteDeadline is used to set write deadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	err := c.acceptStream()
	if err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}

type listener struct {
	rawConn net.PacketConn // see Conn
	quic.Listener
	timeout time.Duration
}

func (l *listener) Accept() (net.Conn, error) {
	session, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := Conn{
		session: session,
		timeout: l.timeout,
	}
	return &conn, nil
}

func (l *listener) Close() error {
	err := l.Listener.Close()
	_ = l.rawConn.Close()
	return err
}
