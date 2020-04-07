package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/For-ACGN/quic-socks"
)

func main() {
	var (
		localAddr  string
		remoteAddr string
		password   string
		certPath   string
		preConns   int
		socksUser  string
		socksPwd   string
	)
	flag.StringVar(&localAddr, "l", "localhost:1080", "local bind address")
	flag.StringVar(&remoteAddr, "r", "localhost:1523", "server bind address")
	flag.StringVar(&password, "p", "123456", "password")
	flag.StringVar(&certPath, "c", "cert.pem", "tls certificate file path")
	flag.IntVar(&preConns, "pre", 128, "the number of the pre-connected connection")
	flag.StringVar(&socksUser, "su", "", "the username about local socks server")
	flag.StringVar(&socksPwd, "sp", "", "the password about local socks server")
	flag.Parse()

	// set certificate
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		fmt.Println("invalid PEM block")
		return
	}
	if block.Type != "CERTIFICATE" {
		fmt.Println("invalid PEM block type")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	tlsConfig.RootCAs.AddCert(cert)

	// connect quic-socks server
	client, err := socks.NewClient(remoteAddr, []byte(password), &tlsConfig)
	if err != nil {
		fmt.Println(err)
		return
	}

	// accept client conn
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	log.SetOutput(ioutil.Discard)

	wg := sync.WaitGroup{}
	// start pre-connected worker
	stopSignal := make(chan struct{})
	connQueue := make(chan net.Conn, preConns)
	for i := 0; i < preConns/10+1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopSignal:
					return
				default:
				}
				conn, err := client.Dial()
				if err != nil {
					fmt.Println("failed to dial quic socks:", err)
					time.Sleep(time.Second)
					continue
				}
				select {
				case connQueue <- conn:
				case <-stopSignal:
					return
				}
			}
		}()
	}

	// handle signal
	wg.Add(1)
	go func() {
		defer wg.Done()
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Kill, os.Interrupt)
		<-signalChan
		close(stopSignal)
		_ = listener.Close()
	}()

	socksUserBytes := []byte(socksUser)
	socksPwdBytes := []byte(socksPwd)

	// handle conn
	var tempDelay time.Duration
	max := time.Second
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > max {
					tempDelay = max
				}
				fmt.Printf("accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			break
		}
		tempDelay = 0
		go handleConn(connQueue, conn, socksUserBytes, socksPwdBytes)
	}
	wg.Wait()
}

const (
	version5 uint8 = 0x05
	reserve  uint8 = 0x00
	// auth method
	usernamePassword uint8 = 0x02

	// auth
	usernamePasswordVersion uint8 = 0x01
	statusSucceeded         uint8 = 0x00
	statusFailed            uint8 = 0x01
	notRequired             uint8 = 0x00
	// cmd
	connect uint8 = 0x01
	// address
	ipv4 uint8 = 0x01
	fqdn uint8 = 0x03
	ipv6 uint8 = 0x04
	// reply
	succeeded   uint8 = 0x00
	connRefused uint8 = 0x05
)

var (
	success    = []byte{version5, succeeded, reserve, ipv4, 0, 0, 0, 0, 0, 0}
	connRefuse = []byte{version5, connRefused, reserve, ipv4, 0, 0, 0, 0, 0, 0}
)

func authenticate(conn net.Conn, su, sp []byte) bool {
	var err error
	if len(su) != 0 && len(sp) != 0 {
		_, err = conn.Write([]byte{version5, usernamePassword})
		if err != nil {
			return false
		}
		buf := make([]byte, 16)
		// read username and password version
		_, err = io.ReadAtLeast(conn, buf[:1], 1)
		if err != nil {
			return false
		}
		if buf[0] != usernamePasswordVersion {
			return false
		}
		// read username length
		_, err = io.ReadAtLeast(conn, buf[:1], 1)
		if err != nil {
			return false
		}
		l := int(buf[0])
		if l > len(buf) {
			buf = make([]byte, l)
		}
		// read username
		_, err = io.ReadAtLeast(conn, buf[:l], l)
		if err != nil {
			return false
		}
		username := make([]byte, l)
		copy(username, buf[:l])
		// read password length
		_, err = io.ReadAtLeast(conn, buf[:1], 1)
		if err != nil {
			return false
		}
		l = int(buf[0])
		if l > len(buf) {
			buf = make([]byte, l)
		}
		// read password
		_, err = io.ReadAtLeast(conn, buf[:l], l)
		if err != nil {
			return false
		}
		password := make([]byte, l)
		copy(password, buf[:l])
		// write username password version
		_, err = conn.Write([]byte{usernamePasswordVersion})
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare(su, username) != 1 ||
			subtle.ConstantTimeCompare(sp, password) != 1 {
			_, _ = conn.Write([]byte{statusFailed})
			return false
		}
		_, err = conn.Write([]byte{statusSucceeded})
	} else {
		_, err = conn.Write([]byte{version5, notRequired})
	}
	if err != nil {
		return false
	}
	return true
}

// simple socks5 server, handle socks5 client
func handleConn(queue chan net.Conn, conn net.Conn, su, sp []byte) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic:", r)
		}
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(time.Minute))

	// read version & authentication methods number
	buffer := make([]byte, 16)
	_, err := io.ReadFull(conn, buffer[:2])
	if err != nil {
		fmt.Println("read socks5 version failed:", err)
		return
	}
	if buffer[0] != version5 {
		fmt.Printf("unexpected protocol version %d\n", buffer[0])
		return
	}
	authNum := int64(buffer[1])
	if authNum == 0 {
		fmt.Println("authentication methods number is 0")
		return
	}

	// read authentication methods(discard)
	_, err = io.Copy(ioutil.Discard, io.LimitReader(conn, authNum))
	if err != nil {
		fmt.Println("read authentication methods failed:", err)
		return
	}

	if !authenticate(conn, su, sp) {
		return
	}

	// receive connect target
	// version | cmd | reserve | address type
	_, err = io.ReadAtLeast(conn, buffer[:4], 4)
	if err != nil {
		fmt.Println("receive connect target failed:", err)
		return
	}
	if buffer[0] != version5 {
		fmt.Printf("unexpected protocol version %d\n", buffer[0])
		return
	}
	if buffer[1] != connect {
		fmt.Printf("unsupport cmd %d\n", buffer[1])
		return
	}
	// buffer[2] is reserve

	// read address
	var host string
	switch buffer[3] {
	case ipv4:
		_, err = io.ReadAtLeast(conn, buffer[:net.IPv4len], net.IPv4len)
		if err != nil {
			fmt.Println("read IPv4 failed:", err)
			return
		}
		host = net.IP(buffer[:4]).String()
	case ipv6:
		_, err = io.ReadAtLeast(conn, buffer[:net.IPv6len], net.IPv6len)
		if err != nil {
			fmt.Println("read IPv6 failed:", err)
			return
		}
		host = "[" + net.IP(buffer[:net.IPv6len]).String() + "]"
	case fqdn:
		// get FQDN length
		_, err = io.ReadAtLeast(conn, buffer[:1], 1)
		if err != nil {
			fmt.Println("read FQDN length failed:", err)
			return
		}
		l := int(buffer[0])
		if l > len(buffer) {
			buffer = make([]byte, l)
		}
		_, err = io.ReadAtLeast(conn, buffer[:l], l)
		if err != nil {
			fmt.Println("read FQDN failed:", err)
			return
		}
		host = string(buffer[:l])
	default:
		fmt.Printf("address type not supported %d\n", buffer[0])
		return
	}

	// read port
	_, err = io.ReadAtLeast(conn, buffer[:2], 2)
	if err != nil {
		fmt.Println("read port failed:", err)
		return
	}

	// start connect to quic-socks server
	port := binary.BigEndian.Uint16(buffer[:2])
	var remote net.Conn
startCopy:
	for {
		select {
		case preConn := <-queue:
			remote, err = socks.Connect(preConn, host, port)
			if err != nil {
				_ = preConn.Close()
				errStr := err.Error()
				if strings.Contains(errStr, "invalid password") ||
					strings.Contains(errStr, "failed to connect target") {
					_, _ = conn.Write(connRefuse)
					fmt.Println(errStr)
					return
				}
				continue
			}
			break startCopy
		case <-time.After(30 * time.Second):
			fmt.Println("get pre-connection timeout")
			return
		}
	}
	defer func() { _ = remote.Close() }()
	// write reply
	// padding ipv4 + 0.0.0.0 + 0(port)
	_, err = conn.Write(success)
	if err != nil {
		fmt.Println("failed to write reply:", err)
		return
	}
	// copy
	_ = conn.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	go func() { _, _ = io.Copy(conn, remote) }()
	_, _ = io.Copy(remote, conn)
}
