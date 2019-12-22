package socks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_Connect(t *testing.T) {
	// generate server
	tlsCert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	require.NoError(t, err)
	serverTLS := tls.Config{Certificates: []tls.Certificate{tlsCert}}
	server, err := NewServer("localhost:8989", []byte("test"), &serverTLS)
	require.NoError(t, err)
	defer server.Close()
	go func() { _ = server.ListenAndServe() }()

	clientTLS := tls.Config{RootCAs: x509.NewCertPool()}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	clientTLS.RootCAs.AddCert(cert)
	client, err := NewClient("localhost:8989", []byte("test"), &clientTLS)

	hc := http.Client{}
	hc.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			i, _ := strconv.Atoi(port)
			conn, err := client.Dial()
			require.NoError(t, err)
			return Connect(conn, host, uint16(i))
		}}
	resp, err := hc.Get("https://github.com/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Log(string(b))
}
