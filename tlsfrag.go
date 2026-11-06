package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// maxRecordLen bounds the TLS record we are willing to buffer (16 KiB plaintext
// plus generous overhead).
const maxRecordLen = 16384 + 2048

// fragModes lists the supported ways of cutting the ClientHello.
var fragModes = []string{"both", "record", "tcp", "none"}

// findSNI returns the offset and length of the host_name inside a TLS record
// holding a ClientHello. ok is false if rec is not a ClientHello or has no SNI.
func findSNI(rec []byte) (off, n int, ok bool) {
	defer func() { // malformed input: any out-of-range access means "no SNI"
		if recover() != nil {
			off, n, ok = 0, 0, false
		}
	}()
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x01 {
		return 0, 0, false
	}
	p := 9                                         // record header (5) + handshake type and length (4)
	p += 2 + 32                                    // client_version + random
	p += 1 + int(rec[p])                           // session_id
	p += 2 + int(binary.BigEndian.Uint16(rec[p:])) // cipher_suites
	p += 1 + int(rec[p])                           // compression_methods
	extEnd := p + 2 + int(binary.BigEndian.Uint16(rec[p:]))
	p += 2
	if extEnd > len(rec) {
		extEnd = len(rec)
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(rec[p:])
		l := int(binary.BigEndian.Uint16(rec[p+2:]))
		if typ == 0x0000 { // server_name
			q := p + 4 + 2      // skip server_name_list length
			if rec[q] != 0x00 { // name_type host_name
				return 0, 0, false
			}
			n = int(binary.BigEndian.Uint16(rec[q+1:]))
			off = q + 3
			if n == 0 || off+n > len(rec) {
				return 0, 0, false
			}
			return off, n, true
		}
		p += 4 + l
	}
	return 0, 0, false
}

// fragment cuts one complete ClientHello record so the SNI never appears whole
// in a single piece. Each returned piece is meant to be written separately.
//
//	tcp    - one TLS record, two TCP writes split in the middle of the name
//	record - two TLS records split in the middle of the name, one TCP write
//	both   - two TLS records, sent as three TCP writes (default, most robust)
//	none   - unchanged
func fragment(rec []byte, mode string) [][]byte {
	off, n, ok := findSNI(rec)
	if !ok || mode == "none" {
		return [][]byte{rec}
	}
	cut := off + max(1, n/2)
	switch mode {
	case "tcp":
		return [][]byte{rec[:cut], rec[cut:]}
	case "record", "both":
		body := rec[5:]
		split := cut - 5
		rest := len(body) - split
		rec1 := make([]byte, 0, 5+split)
		rec1 = append(rec1, rec[0], rec[1], rec[2], byte(split>>8), byte(split))
		rec1 = append(rec1, body[:split]...)
		rec2 := make([]byte, 0, 5+rest)
		rec2 = append(rec2, rec[0], rec[1], rec[2], byte(rest>>8), byte(rest))
		rec2 = append(rec2, body[split:]...)
		if mode == "record" {
			return [][]byte{append(rec1, rec2...)}
		}
		mid := 5 + split/2
		return [][]byte{rec1[:mid], rec1[mid:], rec2}
	}
	return [][]byte{rec}
}

// readRecord reads one TLS record. If the stream does not start with a TLS
// handshake record, the first 5 bytes are returned unchanged.
func readRecord(r io.Reader) ([]byte, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[0] != 0x16 {
		return head, nil
	}
	l := int(binary.BigEndian.Uint16(head[3:]))
	if l > maxRecordLen {
		return nil, fmt.Errorf("TLS record too large (%d bytes)", l)
	}
	rec := make([]byte, 5+l)
	copy(rec, head)
	if _, err := io.ReadFull(r, rec[5:]); err != nil {
		return nil, err
	}
	return rec, nil
}

// writePieces writes each piece separately with a pause in between, so the
// kernel sends them as separate TCP segments (Go enables TCP_NODELAY).
func writePieces(w io.Writer, pieces [][]byte, delay time.Duration) error {
	for i, p := range pieces {
		if _, err := w.Write(p); err != nil {
			return err
		}
		if i < len(pieces)-1 && delay > 0 {
			time.Sleep(delay)
		}
	}
	return nil
}

// splitConn fragments the first ClientHello written through it. It is used by
// "snisplit check" to run a real TLS handshake with the split applied.
type splitConn struct {
	net.Conn
	mode  string
	delay time.Duration
	done  bool
}

func (c *splitConn) Write(b []byte) (int, error) {
	if c.done || len(b) < 5 || b[0] != 0x16 {
		c.done = true
		return c.Conn.Write(b)
	}
	c.done = true
	l := 5 + int(binary.BigEndian.Uint16(b[3:]))
	if l > len(b) {
		return c.Conn.Write(b)
	}
	pieces := fragment(b[:l], c.mode)
	if l < len(b) {
		pieces = append(pieces, b[l:])
	}
	if err := writePieces(c.Conn, pieces, c.delay); err != nil {
		return 0, err
	}
	return len(b), nil
}

func validMode(m string) bool {
	for _, x := range fragModes {
		if m == x {
			return true
		}
	}
	return false
}
