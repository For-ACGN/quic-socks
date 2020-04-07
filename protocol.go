package socks

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/pkg/errors"
)

const nextProto = "h3-27"

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
	respSize = 1
)

const (
	typeIPv4 uint8 = iota + 1
	typeIPv6
	typeFQDN
)

const (
	authOK uint8 = iota + 1
	respOK
	respInvalidPWD
	respInvalidHost
	respConnectFailed
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

func unpackHostData(u io.Reader) (string, error) {
	typ := make([]byte, typeSize)
	_, err := u.Read(typ)
	if err != nil {
		return "", err
	}
	var host string
	switch typ[0] {
	case typeIPv4:
		ip := make([]byte, net.IPv4len)
		_, err = io.ReadFull(u, ip)
		if err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case typeIPv6:
		ip := make([]byte, net.IPv6len)
		_, err = io.ReadFull(u, ip)
		if err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case typeFQDN:
		fqdnLen := make([]byte, fqdnSize)
		_, err = u.Read(fqdnLen)
		if err != nil {
			return "", err
		}
		fqdn := make([]byte, int(fqdnLen[0]))
		_, err = io.ReadFull(u, fqdn)
		if err != nil {
			return "", err
		}
		host = string(fqdn)
	default:
		return "", errors.New("invalid type")
	}
	port := make([]byte, portSize)
	_, err = io.ReadFull(u, port)
	if err != nil {
		return "", err
	}
	portStr := strconv.Itoa(int(binary.BigEndian.Uint16(port)))
	return net.JoinHostPort(host, portStr), nil
}

type Response uint8

func (r Response) Error() string {
	switch uint8(r) {
	case respInvalidPWD:
		return "invalid password"
	case respConnectFailed:
		return "failed to connect target"
	default:
		return "unknown error"
	}
}
