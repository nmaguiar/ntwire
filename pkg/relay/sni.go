// Package relay implements the public-facing TLS passthrough relay: it
// routes inbound connections by ClientHello SNI to an ntwire-server that
// dialed back over an authenticated control connection, without ever
// terminating the client's TLS session.
package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	maxClientHelloRecords = 4
	maxClientHelloBytes   = 16 * 1024

	recordTypeHandshake = 0x16
	handshakeTypeClient = 0x01
	extensionServerName = 0x0000
	serverNameTypeHost  = 0x00
	tlsRecordHeaderSize = 5
	handshakeHeaderSize = 4
)

// peekClientHello reads whole TLS records off r until a complete ClientHello
// handshake message has been reassembled, returning the normalized SNI (empty
// if none was present) and every raw byte consumed so the caller can replay
// them verbatim into the dial-back connection. It performs no I/O policy of
// its own (no deadlines, no size limits beyond the hard caps below) — that is
// the caller's responsibility.
func peekClientHello(r io.Reader) (sni string, raw []byte, err error) {
	var buf bytes.Buffer // raw record bytes, returned verbatim for replay
	var msg bytes.Buffer // reassembled handshake message body (post record-layer)
	var records int

	for {
		var header [tlsRecordHeaderSize]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return "", nil, fmt.Errorf("reading TLS record header: %w", err)
		}
		if header[0] != recordTypeHandshake {
			return "", nil, fmt.Errorf("not a TLS handshake record (first byte 0x%02x)", header[0])
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		records++
		if records > maxClientHelloRecords {
			return "", nil, fmt.Errorf("ClientHello spans too many TLS records (>%d)", maxClientHelloRecords)
		}
		if buf.Len()+tlsRecordHeaderSize+length > maxClientHelloBytes {
			return "", nil, fmt.Errorf("ClientHello exceeds %d byte cap", maxClientHelloBytes)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return "", nil, fmt.Errorf("reading TLS record payload: %w", err)
		}
		buf.Write(header[:])
		buf.Write(payload)
		msg.Write(payload)

		if msg.Len() < handshakeHeaderSize {
			continue
		}
		body := msg.Bytes()
		if body[0] != handshakeTypeClient {
			return "", nil, fmt.Errorf("not a ClientHello handshake message (type 0x%02x)", body[0])
		}
		msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		if msg.Len() < handshakeHeaderSize+msgLen {
			continue // handshake message fragmented across further records
		}
		sni, err = parseClientHelloServerName(body[handshakeHeaderSize : handshakeHeaderSize+msgLen])
		if err != nil {
			return "", nil, err
		}
		return sni, buf.Bytes(), nil
	}
}

// parseClientHelloServerName walks a ClientHello handshake body (the bytes
// after the 4-byte handshake header) and returns the normalized SNI host
// name, or "" if the extension is absent.
func parseClientHelloServerName(b []byte) (string, error) {
	// legacy_version(2) | random(32)
	if len(b) < 34 {
		return "", fmt.Errorf("ClientHello too short")
	}
	b = b[34:]

	// session_id: 1-byte length prefix
	b, err := skipLengthPrefixed(b, 1)
	if err != nil {
		return "", fmt.Errorf("session_id: %w", err)
	}
	// cipher_suites: 2-byte length prefix
	b, err = skipLengthPrefixed(b, 2)
	if err != nil {
		return "", fmt.Errorf("cipher_suites: %w", err)
	}
	// compression_methods: 1-byte length prefix
	b, err = skipLengthPrefixed(b, 1)
	if err != nil {
		return "", fmt.Errorf("compression_methods: %w", err)
	}
	if len(b) == 0 {
		return "", nil // no extensions present, therefore no SNI
	}
	// extensions: 2-byte length prefix wrapping the whole extensions block
	if len(b) < 2 {
		return "", fmt.Errorf("extensions: truncated length")
	}
	extLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if len(b) < extLen {
		return "", fmt.Errorf("extensions: truncated body")
	}
	extensions := b[:extLen]

	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return "", fmt.Errorf("extension header truncated")
		}
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extDataLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extDataLen {
			return "", fmt.Errorf("extension body truncated")
		}
		data := extensions[:extDataLen]
		extensions = extensions[extDataLen:]
		if extType != extensionServerName {
			continue
		}
		return parseServerNameExtension(data)
	}
	return "", nil
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("server_name extension truncated")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < listLen {
		return "", fmt.Errorf("server_name list truncated")
	}
	data = data[:listLen]
	for len(data) > 0 {
		if len(data) < 3 {
			return "", fmt.Errorf("server_name entry truncated")
		}
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < nameLen {
			return "", fmt.Errorf("server_name host truncated")
		}
		name := data[:nameLen]
		data = data[nameLen:]
		if nameType != serverNameTypeHost {
			continue // reserved entry types are not host names; skip
		}
		return normalizeSNI(string(name)), nil
	}
	return "", nil
}

func normalizeSNI(s string) string {
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".")
	return s
}

// skipLengthPrefixed consumes a length-prefixed field (prefixLen bytes of
// big-endian length, then that many bytes of value) and returns the
// remainder of b.
func skipLengthPrefixed(b []byte, prefixLen int) ([]byte, error) {
	if len(b) < prefixLen {
		return nil, fmt.Errorf("truncated length prefix")
	}
	var n int
	for i := 0; i < prefixLen; i++ {
		n = n<<8 | int(b[i])
	}
	b = b[prefixLen:]
	if len(b) < n {
		return nil, fmt.Errorf("truncated value")
	}
	return b[n:], nil
}
