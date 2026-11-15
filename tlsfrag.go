package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// maxRecordLen bounds the TLS record we are willing to buffer (16 KiB plaintext
// plus generous overhead).
const maxRecordLen = 16384 + 2048

// fragModes lists the supported ways of cutting the ClientHello. See plan.
var fragModes = []string{"both", "record", "tcp", "chunk", "oob", "disorder", "slow", "none"}

// slowDelayNS is the pause (ns) "slow" leaves between pieces, longer than a
// DPI box usually waits to put a stream back together. The strategy sets it.
var slowDelayNS atomic.Int64

func init() { slowDelayNS.Store(int64(300 * time.Millisecond)) }

// sleepForSend gives the kernel time to put a low-TTL piece on the wire before
// the TTL is restored.
func sleepForSend() { time.Sleep(5 * time.Millisecond) }

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

// piece is one write of a split ClientHello.
type piece struct {
	data   []byte
	lowTTL bool          // sent with TTL 1: dropped by the first router, then resent by the kernel
	oob    bool          // the last byte is sent as TCP urgent data, which the server's stack drops
	wait   time.Duration // pause after this piece; 0 means the configured delay
}

// plan turns a ClientHello record into the writes for mode:
//
//	both, record, tcp - see fragment
//	chunk    - the name cut into 4-byte TLS records, each its own TCP write,
//	           after a first write of a single byte
//	oob      - two records with one extra urgent byte between them: a DPI box
//	           that does not drop urgent data parses garbage
//	disorder - two records, the first sent with TTL 1 so it never reaches the
//	           ISP; the box sees the second half first, the server gets the
//	           first half when the kernel retransmits it (adds ~0.3-1 s)
//	slow     - like both, with a long pause between pieces
func plan(rec []byte, mode string) []piece {
	off, n, ok := findSNI(rec)
	if !ok || mode == "none" {
		return []piece{{data: rec}}
	}
	wrap := func(bs [][]byte) []piece {
		ps := make([]piece, len(bs))
		for i, b := range bs {
			ps[i] = piece{data: b}
		}
		return ps
	}
	switch mode {
	case "chunk":
		var cuts []int // offsets into the record body
		for i := 2; i < n; i += 4 {
			cuts = append(cuts, off-5+i)
		}
		recs := splitRecords(rec, cuts)
		ps := []piece{{data: recs[0][:1]}, {data: recs[0][1:]}}
		for _, r := range recs[1:] {
			ps = append(ps, piece{data: r})
		}
		return ps
	case "oob":
		recs := splitRecords(rec, []int{off - 5 + max(1, n/2)})
		first := append(append([]byte(nil), recs[0]...), 'x')
		return []piece{{data: first, oob: true}, {data: recs[1]}}
	case "disorder":
		recs := splitRecords(rec, []int{off - 5 + max(1, n/2)})
		return []piece{{data: recs[0], lowTTL: true}, {data: recs[1]}}
	case "slow":
		ps := wrap(fragment(rec, "both"))
		for i := range ps {
			ps[i].wait = time.Duration(slowDelayNS.Load())
		}
		return ps
	}
	return wrap(fragment(rec, mode))
}

// splitRecords cuts the handshake data of one TLS record at the given body
// offsets (ascending) and returns one complete record per part.
func splitRecords(rec []byte, cuts []int) [][]byte {
	body := rec[5:]
	var out [][]byte
	prev := 0
	for _, c := range append(cuts, len(body)) {
		if c <= prev || c > len(body) {
			continue
		}
		part := body[prev:c]
		r := make([]byte, 0, 5+len(part))
		r = append(r, rec[0], rec[1], rec[2], byte(len(part)>>8), byte(len(part)))
		out = append(out, append(r, part...))
		prev = c
	}
	return out
}

// sendPieces writes the pieces of a plan. lowTTL and oob need a real TCP
// socket; on anything else they degrade to plain writes.
func sendPieces(c net.Conn, ps []piece, delay time.Duration) error {
	for i, p := range ps {
		var err error
		switch {
		case p.lowTTL:
			err = writeLowTTL(c, p.data)
		case p.oob:
			err = writeOOB(c, p.data)
		default:
			_, err = c.Write(p.data)
		}
		if err != nil {
			return err
		}
		if i < len(ps)-1 {
			w := p.wait
			if w == 0 {
				w = delay
			}
			if w > 0 {
				time.Sleep(w)
			}
		}
	}
	return nil
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
	pieces := plan(b[:l], c.mode)
	if l < len(b) {
		pieces = append(pieces, piece{data: b[l:]})
	}
	if err := sendPieces(c.Conn, pieces, c.delay); err != nil {
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
