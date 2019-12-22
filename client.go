package socks

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go"
)

type Client struct {
	address   string
	hash      []byte
	tlsConfig *tls.Config
	session   quic.Session // wait quic-go support BBR
}

func NewClient(address string, password []byte, tlsConfig *tls.Config) (*Client, error) {
	// skip QUIC debug log about BBR
	err := os.Setenv("GODEBUG", "bbr=1")
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(password)
	client := Client{
		address:   address,
		hash:      hash[:],
		tlsConfig: tlsConfig,
	}
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, nextProto)
	return &client, nil
}

func (c *Client) Dial() (net.Conn, error) {
	session, err := quic.DialAddr(c.address, c.tlsConfig, nil)
	if err != nil {
		return nil, err
	}
	conn, err := newConn(session)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	paddingSize := 128 + rand.Intn(128)
	padding := make([]byte, paddingSize)
	for i := 0; i < paddingSize; i++ {
		padding[i] = byte(rand.Intn(256))
	}
	tempHash := sha256.New()
	tempHash.Write(c.hash)
	tempHash.Write(padding)
	buf := bytes.Buffer{}
	buf.Write(tempHash.Sum(nil))
	buf.Write(padding)
	_, err = io.Copy(conn, &buf)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func Connect(conn net.Conn, host string, port uint16) (net.Conn, error) {
	hostData, err := packHostData(host, port)
	if err != nil {
		return nil, err
	}
	// send request
	_, err = conn.Write(hostData)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// receive response
	resp := make([]byte, respSize)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp[0] != respOK {
		_ = conn.Close()
		return nil, Response(resp[0])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
