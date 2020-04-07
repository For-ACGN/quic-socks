package socks

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"io"
	"net"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/pkg/errors"
)

type Server struct {
	hash     []byte // password hash
	listener *listener
}

func NewServer(address string, password []byte, tlsConfig *tls.Config) (*Server, error) {
	// skip QUIC debug log about BBR
	err := os.Setenv("GODEBUG", "bbr=1")
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, nextProto)
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	quicCfg := quic.Config{
		HandshakeTimeout: 30 * time.Second,
		IdleTimeout:      10 * time.Minute,
		KeepAlive:        true,
	}
	quicListener, err := quic.Listen(conn, tlsConfig, &quicCfg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	listener := listener{
		rawConn:  conn,
		Listener: quicListener,
		timeout:  30 * time.Second,
	}
	hash := sha256.Sum256(password)
	return &Server{
		hash:     hash[:],
		listener: &listener,
	}, nil
}

func (s *Server) ListenAndServe() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() {
		recover()
		_ = conn.Close()

	}()
	_ = conn.SetDeadline(time.Now().Add(time.Minute))
	// read password hash with random data
	tempHash := make([]byte, sha256.Size)
	_, err := io.ReadFull(conn, tempHash)
	if err != nil {
		return
	}
	buf := make([]byte, 256)
	limitedReader := io.LimitReader(conn, 256)
	hash := sha256.New()
	hash.Write(s.hash)
	for {
		n, err := limitedReader.Read(buf)
		if err != nil {
			return
		}
		hash.Write(buf[:n])
		if subtle.ConstantTimeCompare(hash.Sum(nil), tempHash) == 1 {
			break
		}
	}
	_, err = conn.Write([]byte{authOK})
	if err != nil {
		return
	}

	_ = conn.SetDeadline(time.Time{})
	// get connect host
	host, err := unpackHostData(conn)
	if err != nil {
		_, _ = conn.Write([]byte{respInvalidHost})
		return
	}
	remote, err := net.Dial("tcp", host)
	if err != nil {
		_, _ = conn.Write([]byte{respConnectFailed})
		return
	}
	defer func() { _ = remote.Close() }()
	_, _ = conn.Write([]byte{respOK})

	// copy
	go func() {
		defer func() { recover() }()
		_, _ = io.Copy(conn, remote)
	}()
	_, _ = io.Copy(remote, conn)
}

func (s *Server) Close() {
	_ = s.listener.Close()
}
