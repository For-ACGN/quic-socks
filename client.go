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
	rAddr, err := net.ResolveUDPAddr("udp", c.address)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	var success bool
	defer func() {
		if !success {
			_ = udpConn.Close()
		}
	}()
	quicCfg := quic.Config{
		HandshakeTimeout: 30 * time.Second,
		IdleTimeout:      10 * time.Minute,
		KeepAlive:        true,
	}
	session, err := quic.Dial(udpConn, rAddr, c.address, c.tlsConfig, &quicCfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			_ = session.CloseWithError(0, "no error")
		}
	}()
	stream, err := session.OpenStreamSync()
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			_ = stream.Close()
		}
	}()
	// write data for prevent block
	_ = stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err = stream.Write([]byte{0})
	if err != nil {
		return nil, err
	}

	conn := &Conn{rawConn: udpConn, session: session, stream: stream}
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

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
		return nil, err
	}
	authResp := make([]byte, 1)
	_, err = io.ReadFull(conn, authResp)
	if err != nil {
		return nil, err
	}
	if authResp[0] != authOK {
		return nil, Response(authResp[0])
	}
	success = true
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
