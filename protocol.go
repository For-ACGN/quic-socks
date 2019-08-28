package socks

import (
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

// client connect
// type can be 0x00(IPv4), 0x01(IPv6), 0x02(FQDN)
//
// host size = 4             (type = IPv4)
// host size = 16            (type = IPv6)
// host size = 1 + FQDN size (type = FQDN)
// +-----+-------+------+--------+
// | pwd | type  | host |  port  |
// +-----+-------+------+--------+
// | var | uint8 | var  | uint16 |
// +-----+-------+------+--------+

const (
	typeSize = 1
	fqdnSize = 1
	portSize = 2

	typeIPv4 uint8 = 0x00
	typeIPv6 uint8 = 0x01
	typeFQDN uint8 = 0x02

	respOK            uint8 = 0x00
	respInvalidPWD    uint8 = 0x01
	respConnectFailed uint8 = 0x02
)

// type + host + port
func packHostData(host string, port uint16) ([]byte, error) {
	var hostData []byte
	ip := net.ParseIP(host)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil { // IPv4
			hostData = make([]byte, typeSize+net.IPv4len)
			hostData[0] = typeIPv4
			copy(hostData[typeSize:], ip4)
		} else { // IPv6
			ip6 := ip.To16()
			if ip6 != nil {
				hostData = make([]byte, typeSize+net.IPv6len)
				hostData[0] = typeIPv6
				copy(hostData[typeSize:], ip6)
			} else {
				return nil, errors.New("unknown host type")
			}
		}
	} else { // FQDN
		if len(host) > 255 {
			return nil, errors.New("FQDN too long")
		}
		h := []byte(host)
		l := len(h)
		hostData = make([]byte, typeSize+fqdnSize+l)
		hostData[0] = typeFQDN
		hostData[1] = byte(l)
		copy(hostData[typeSize+fqdnSize:], h)
	}
	// set port
	portData := make([]byte, portSize)
	binary.BigEndian.PutUint16(portData, port)
	return append(hostData, portData...), nil
}

type Response uint8

func (r Response) Error() string {
	switch uint8(r) {
	case respInvalidPWD:
		return "invalid password"
	case respConnectFailed:
		return "connect target failed"
	default:
		return "unknown error"
	}
}
