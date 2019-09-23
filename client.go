package socks

import (
	"context"
	"crypto/tls"
	"net"
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/pkg/errors"
)

type Client struct {
	address   string
	password  []byte
	tlsConfig *tls.Config
	session   quic.Session // wait quic-go support BBR
}

func NewClient(address string, tlsConfig *tls.Config, password string) (*Client, error) {
	err := os.Setenv("GODEBUG", "bbr=1")
	if err != nil {
		return nil, err
	}
	c := Client{
		address:   address,
		password:  []byte(password),
		tlsConfig: tlsConfig,
	}
	if len(c.password) > 32 {
		return nil, errors.New("password size > 32")
	}
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
	/*
		err = c.dial()
		if err != nil {
			return nil, err
		}
	*/
	return &c, nil
}

func (c *Client) dial() error {
	var err error
	cfg := quic.Config{MaxIncomingStreams: 4096}
	c.session, err = quic.DialAddr(c.address, c.tlsConfig, &cfg)
	return err
}

// Connect
func (c *Client) Connect(host string, port uint16) (net.Conn, error) {
	// wait quic-go support BBR
	/*
		var (
			stream quic.Stream
			err    error
		)
		for i := 0; i < 3; i++ {
			stream, err = c.session.OpenStream()
			if err != nil {
				// reconnect
				err = c.dial()
				if err != nil {
					return nil, err
				}
			} else {
				break
			}
		}
	*/
	session, err := quic.DialAddr(c.address, c.tlsConfig, nil)
	if err != nil {
		return nil, err
	}
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	str := &deadlineStream{Stream: stream}
	hostData, err := packHostData(host, port)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// send request
	_, err = str.Write(append(c.password, hostData...))
	if err != nil {
		_ = stream.Close()
		return nil, err
	}

	// receive response
	resp := make([]byte, respSize)
	_, err = str.Read(resp)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if resp[0] != respOK {
		_ = stream.Close()
		return nil, Response(resp[0])
	}
	return newConn(session, stream), nil
}

func (c *Client) Close() {
	// _ = c.session.Close()
}
