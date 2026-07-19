package utls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"

	tlsfingerprint "github.com/refraction-networking/utls"
)

func Client(ctx context.Context, conn net.Conn, cfg *tls.Config, fingerprint string) (net.Conn, error) {
	id, ok := clientHelloID(fingerprint)
	if !ok {
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tlsConn, nil
	}
	uConn := tlsfingerprint.UClient(conn, convertConfig(cfg), id)
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uConn, nil
}

func clientHelloID(name string) (tlsfingerprint.ClientHelloID, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "off", "none", "native", "go":
		return tlsfingerprint.ClientHelloID{}, false
	case "chrome", "chrome-auto", "chrome_auto":
		return tlsfingerprint.HelloChrome_Auto, true
	case "firefox", "firefox-auto", "firefox_auto":
		return tlsfingerprint.HelloFirefox_Auto, true
	case "ios", "safari-ios":
		return tlsfingerprint.HelloIOS_Auto, true
	case "randomized", "random":
		return tlsfingerprint.HelloRandomized, true
	default:
		return tlsfingerprint.HelloChrome_Auto, true
	}
}

func convertConfig(cfg *tls.Config) *tlsfingerprint.Config {
	if cfg == nil {
		return &tlsfingerprint.Config{}
	}
	return &tlsfingerprint.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		NextProtos:         append([]string(nil), cfg.NextProtos...),
		Certificates:       convertCertificates(cfg.Certificates),
	}
}

func convertCertificates(items []tls.Certificate) []tlsfingerprint.Certificate {
	if len(items) == 0 {
		return nil
	}
	out := make([]tlsfingerprint.Certificate, 0, len(items))
	for _, item := range items {
		out = append(out, tlsfingerprint.Certificate{
			Certificate:                  cloneByteSlices(item.Certificate),
			PrivateKey:                   item.PrivateKey,
			SupportedSignatureAlgorithms: convertSignatureSchemes(item.SupportedSignatureAlgorithms),
			OCSPStaple:                   append([]byte(nil), item.OCSPStaple...),
			SignedCertificateTimestamps:  cloneByteSlices(item.SignedCertificateTimestamps),
			Leaf:                         cloneCertificate(item.Leaf),
		})
	}
	return out
}

func convertSignatureSchemes(items []tls.SignatureScheme) []tlsfingerprint.SignatureScheme {
	if len(items) == 0 {
		return nil
	}
	out := make([]tlsfingerprint.SignatureScheme, 0, len(items))
	for _, item := range items {
		out = append(out, tlsfingerprint.SignatureScheme(uint16(item)))
	}
	return out
}

func cloneByteSlices(items [][]byte) [][]byte {
	if len(items) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		out = append(out, append([]byte(nil), item...))
	}
	return out
}

func cloneCertificate(cert *x509.Certificate) *x509.Certificate {
	if cert == nil {
		return nil
	}
	return cert
}
