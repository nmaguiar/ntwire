package egressrouter

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type probeTarget struct {
	destination Destination
	https       *url.URL
}

func parseProbe(raw string) (probeTarget, error) {
	if !strings.Contains(raw, "://") {
		dst, err := destination(raw)
		if err != nil {
			return probeTarget{}, errors.New("probe target must be host:port or an HTTPS URL")
		}
		return probeTarget{destination: dst}, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || len(raw) > 2048 {
		return probeTarget{}, errors.New("HTTPS probe target must omit credentials, query and fragment")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dst, err := destination(net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return probeTarget{}, errors.New("invalid HTTPS probe authority")
	}
	return probeTarget{destination: dst, https: u}, nil
}

func measureHTTPS(parent context.Context, conn net.Conn, origin *url.URL, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	secure := tls.Client(conn, &tls.Config{ServerName: origin.Hostname(), MinVersion: tls.VersionTLS12})
	start := time.Now()
	if err := secure.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, origin.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Close = true
	if err = req.Write(secure); err != nil {
		return 0, err
	}
	reader := bufio.NewReaderSize(secure, 1024)
	if _, err = reader.Peek(1); err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	// A bounded status line avoids parsing arbitrary headers or downloading
	// an origin's response body. Redirects are never followed.
	line, err := reader.ReadSlice('\n')
	if err != nil || (!strings.HasPrefix(string(line), "HTTP/1.1 2") && !strings.HasPrefix(string(line), "HTTP/1.0 2")) {
		return 0, errors.New("HTTPS probe did not return a success status")
	}
	return elapsed, nil
}
