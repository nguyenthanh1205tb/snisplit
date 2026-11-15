//go:build !windows

package main

import (
	"net"
	"syscall"
)

func ttlOpt(c net.Conn) (level, opt int) {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok && a.IP.To4() == nil {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func writeLowTTL(c net.Conn, b []byte) error {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_, err := c.Write(b)
		return err
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	level, opt := ttlOpt(c)
	old := 64
	rc.Control(func(fd uintptr) {
		if v, err := syscall.GetsockoptInt(int(fd), level, opt); err == nil && v > 0 {
			old = v
		}
		syscall.SetsockoptInt(int(fd), level, opt, 1)
	})
	_, werr := c.Write(b)
	sleepForSend()
	rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), level, opt, old) })
	return werr
}

func writeOOB(c net.Conn, b []byte) error {
	tc, ok := c.(*net.TCPConn)
	if !ok || len(b) == 0 {
		_, err := c.Write(b)
		return err
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	werr := rc.Write(func(fd uintptr) bool {
		serr = syscall.Sendto(int(fd), b, syscall.MSG_OOB, nil)
		return serr != syscall.EAGAIN // false: wait until writable and retry
	})
	if werr != nil {
		return werr
	}
	return serr
}
