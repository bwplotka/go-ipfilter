package ipfilter

import (
	"errors"
	"net"
	"strings"
)

var (
	// https://en.wikipedia.org/wiki/Private_network
	privateIps = []net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 0, 0, 0)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.IPv4Mask(255, 240, 0, 0)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 0, 0)},
	}
)

// Condition is just bool condition for whitelisting IP addresses.
type Condition func(net.IP) bool

// OR is an array of conditions with logic OR. If no condition is passed it returns false.
func OR(conditions ...Condition) Condition {
	return func(ip net.IP) bool {
		for _, condition := range conditions {
			if condition(ip) {
				return true
			}
		}
		return false
	}
}

// AND is an array of conditions with logic AND. If no condition is passed it returns false.
func AND(conditions ...Condition) Condition {
	return func(ip net.IP) bool {
		if len(conditions) == 0 {
			return false
		}

		for _, condition := range conditions {
			if !condition(ip) {
				return false
			}
		}
		return true
	}
}

// IsPrivate is condition that returns true only for IPs from a private network (VPN, localhost).
func IsPrivate() Condition {
	return func(ip net.IP) bool {
		if ip.IsLoopback() {
			return true
		}
		for _, ipNet := range privateIps {
			if ipNet.Contains(ip) {
				return true
			}
		}
		return false
	}
}

// IsWhitelisted is an condition that returns true only for IPs from specified IP/network range.
func IsWhitelisted(ips []net.IPNet) Condition {
	return func(ip net.IP) bool {
		for _, ipNet := range ips {
			if ipNet.Contains(ip) {
				return true
			}
		}
		return false
	}
}

// ParseIP parses an IP (or hostport) string into net.IP.
func ParseIP(address string) (ipAddr net.IP, err error) {
	address = strings.TrimSpace(address)

	if strings.Contains(address, ":") {
		var err error
		address, _, err = net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
	}

	ip := net.ParseIP(address)
	if ip == nil {
		return nil, errors.New("Failed to parse IP. net.ParseIP returned nil")
	}
	return ip, nil
}

func SingleIPNet(ip net.IP) net.IPNet {
	return net.IPNet{IP: ip, Mask: net.IPv4Mask(255, 255, 255, 255)}
}
