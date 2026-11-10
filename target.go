package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

func classify(err error) State {
	if err == nil {
		return Open
	}

	if errors.Is(err, context.Canceled) {
		return Canceled
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}

	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return Closed
	}

	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.EHOSTDOWN) {
		return Unreachable
	}

	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsNotFound {
		return Unreachable
	}

	return Error
}

func normalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", fmt.Errorf("portscan: scoped IPv6 is not supported: %q", host)
		}

		return ip.Unmap().String(), nil
	}

	h = strings.ToLower(strings.TrimSuffix(h, "."))
	valid := len(h) > 0 && len(h) <= 253
	numeric := true

	for _, c := range h {
		if (c < '0' || c > '9') && c != '.' {
			numeric = false
		}
	}

	if numeric {
		valid = false
	}

	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			valid = false
			break
		}

		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				valid = false
			}
		}
	}

	if !valid {
		return "", fmt.Errorf("portscan: invalid host %q", host)
	}

	return h, nil
}
