package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/For-ACGN/quic-socks"
)

func main() {
	var (
		localAddr string
		password  string
		certPath  string
		keyPath   string
	)
	flag.StringVar(&localAddr, "l", ":443", "local bind address")
	flag.StringVar(&password, "p", "123456", "password")
	flag.StringVar(&certPath, "c", "cert.pem", "tls certificate file path")
	flag.StringVar(&keyPath, "k", "key.pem", "tls key file path")
	flag.Parse()

	// set certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatal(err)
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	server, err := socks.NewServer(localAddr, &tlsConfig, password)
	if err != nil {
		log.Fatal(err)
	}

	// handle signal
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Kill, os.Interrupt)
		<-signalChan
		server.Close()
	}()

	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
