package socks

import (
	"time"

	"github.com/lucas-clemente/quic-go"
)

type deadlineStream struct {
	quic.Stream
}

func (d *deadlineStream) Read(p []byte) (n int, err error) {
	_ = d.Stream.SetReadDeadline(time.Now().Add(time.Minute))
	return d.Stream.Read(p)
}

func (d *deadlineStream) Write(p []byte) (n int, err error) {
	_ = d.Stream.SetWriteDeadline(time.Now().Add(time.Minute))
	return d.Stream.Write(p)
}
