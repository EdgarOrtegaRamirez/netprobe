// Package tlscheck provides TLS certificate checking functionality.
package tlscheck

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
)

// Check performs a TLS certificate check on the given host.
func Check(host string, port int, timeout time.Duration) models.TLSCertResult {
	start := time.Now()
	result := models.TLSCertResult{
		Host: host,
		Port: port,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // We want to inspect the cert even if invalid
	})
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	defer conn.Close()

	// Get the peer certificates
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.Error = "no certificates presented"
		result.Duration = time.Since(start)
		return result
	}

	// Primary certificate
	cert := certs[0]
	result.Subject = cert.Subject.CommonName
	result.Issuer = cert.Issuer.CommonName
	result.SerialNumber = formatSerial(cert.SerialNumber)
	result.NotBefore = cert.NotBefore
	result.NotAfter = cert.NotAfter
	result.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)

	// Key info
	result.KeyType, result.KeyBits = getKeyInfo(cert)

	// Signature algorithm
	result.SignatureAlgo = cert.SignatureAlgorithm.String()

	// SANs
	for _, name := range cert.DNSNames {
		result.SANs = append(result.SANs, name)
	}
	for _, ip := range cert.IPAddresses {
		result.SANs = append(result.SANs, ip.String())
	}

	// Chain validation
	result.ChainValid = true
	pool := x509.NewCertPool()
	for i, c := range certs {
		if i == 0 {
			continue
		}
		pool.AddCert(c)
	}

	if len(certs) > 1 {
		opts := x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(opts); err != nil {
			result.ChainValid = false
			result.ChainErrors = append(result.ChainErrors, err.Error())
		}
	} else {
		// Self-signed or leaf only
		result.ChainValid = false
		result.ChainErrors = append(result.ChainErrors, "no intermediate/root certificates in chain")
	}

	result.Duration = time.Since(start)
	return result
}

func formatSerial(serial *big.Int) string {
	return strings.ToUpper(fmt.Sprintf("%x", serial.Bytes()))
}

func getKeyInfo(cert *x509.Certificate) (string, int) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return "RSA", pub.N.BitLen()
		}
		return "RSA", 0
	case x509.ECDSA:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return "ECDSA", pub.Curve.Params().BitSize
		}
		return "ECDSA", 0
	case x509.Ed25519:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}
