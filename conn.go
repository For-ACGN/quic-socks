package socks

import (
	"net"

	"github.com/lucas-clemente/quic-go"
)

// conn implement net.Conn
type conn struct {
	session quic.Session
	quic.Stream
}

func newConn(session quic.Session, stream quic.Stream) *conn {
	return &conn{
		session: session,
		Stream:  stream,
	}
}

func (c *conn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c *conn) RemoteAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c *conn) Close() error {
	return c.Stream.Close()
}
