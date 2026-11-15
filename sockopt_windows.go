//go:build windows

package main

import (
	"net"

	"golang.org/x/sys/windows"
)

// ttlOpt returns the socket option that sets the hop limit for c's family.
func ttlOpt(c net.Conn) (level, opt int) {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok && a.IP.To4() == nil {
		return windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS
	}
	return windows.IPPROTO_IP, windows.IP_TTL
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
	old := 128
	rc.Control(func(fd uintptr) {
		if v, err := windows.GetsockoptInt(windows.Handle(fd), level, opt); err == nil && v > 0 {
			old = v
		}
		windows.SetsockoptInt(windows.Handle(fd), level, opt, 1)
	})
	_, werr := c.Write(b)
	sleepForSend()
	rc.Control(func(fd uintptr) { windows.SetsockoptInt(windows.Handle(fd), level, opt, old) })
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
	cerr := rc.Control(func(fd uintptr) {
		// No OVERLAPPED: a plain blocking send, which the docs allow on an
		// overlapped socket.
		buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
		var sent uint32
		serr = windows.WSASend(windows.Handle(fd), &buf, 1, &sent, windows.MSG_OOB, nil, nil)
	})
	if cerr != nil {
		return cerr
	}
	return serr
}
