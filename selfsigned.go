package selfsigned

import (
	"crypto"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"time"
)

const (
	// ECPrivateKeyBlockType is a possible value for pem.Block.Type.
	ECPrivateKeyBlockType = "EC PRIVATE KEY"
	// RSAPrivateKeyBlockType is a possible value for pem.Block.Type.
	RSAPrivateKeyBlockType = "RSA PRIVATE KEY"
	certificateBlockType   = "CERTIFICATE"
	rsaKeySize             = 2048
	duration365d           = time.Hour * 24 * 365
)

// NewPrivateKey creates an RSA private key
func NewPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(cryptorand.Reader, rsaKeySize)
}

// EncodeCertPEM returns PEM-endcoded certificate data
func EncodeCertPEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  certificateBlockType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

// NewSignedCert creates a signed certificate using the given CA certificate and key
func NewSignedCert(cfg *Config, key crypto.Signer, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, error) {
	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	if len(cfg.CommonName) == 0 {
		return nil, fmt.Errorf("must specify a CommonName")
	}
	if len(cfg.Usages) == 0 {
		return nil, fmt.Errorf("must specify at least one ExtKeyUsage")
	}

	certTmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		DNSNames:     cfg.AltNames.DNSNames,
		IPAddresses:  cfg.AltNames.IPs,
		SerialNumber: serial,
		NotBefore:    caCert.NotBefore,
		NotAfter:     time.Now().Add(duration365d).UTC(),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  cfg.Usages,
	}
	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &certTmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)

}

// Config contains the basic fields required for creating a certificate
type Config struct {
	CommonName   string
	Organization []string
	AltNames     AltNames
	Usages       []x509.ExtKeyUsage
}

// AltNames contains the domain names and IP addresses that will be added
// to the API Server's x509 certificate SubAltNames field. The values will
// be passed directly to the x509.Certificate object.
type AltNames struct {
	DNSNames []string
	IPs      []net.IP
}

// NewSelfSignedCACert creates a CA certificate
func NewSelfSignedCACert(cfg Config, key crypto.Signer) (*x509.Certificate, error) {
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: cfg.Organization,
		},
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(duration365d * 25).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDERBytes, err := x509.CreateCertificate(cryptorand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
}

// MarshalPrivateKeyToPEM converts a known private key type of RSA or ECDSA to
// a PEM encoded block or returns an error.
func MarshalPrivateKeyToPEM(privateKey crypto.PrivateKey) ([]byte, error) {
	switch t := privateKey.(type) {
	case *ecdsa.PrivateKey:
		derBytes, err := x509.MarshalECPrivateKey(t)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  ECPrivateKeyBlockType,
			Bytes: derBytes,
		}
		return pem.EncodeToMemory(block), nil
	case *rsa.PrivateKey:
		block := &pem.Block{
			Type:  RSAPrivateKeyBlockType,
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		}
		return pem.EncodeToMemory(block), nil
	default:
		return nil, fmt.Errorf("private key is not a recognized type: %T", privateKey)
	}
}

func x509Cert(certData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	return cert, nil
}

func rsaPrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: " + err.Error())
	}
	return key, nil
}

type Signer struct {
	CAKey  []byte
	CACert []byte
}

type SelfSignedCert struct {
	Signer
	TLSCert []byte
	TLSKey  []byte
}

// NewSelfSignedCertOrDie is a factory to generate very basic self signed certs good for a year.
// It returns a struct of the three files for self signed certs. It does not save a file.
func NewSelfSignedCertOrDie(names []string) *SelfSignedCert {

	signingKey, err := NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to create CA private key %v", err)
	}

	signingCert, err := NewSelfSignedCACert(Config{CommonName: "selfsigned"}, signingKey)
	if err != nil {
		log.Fatalf("Failed to create CA cert for apiserver %v", err)
	}

	caCert := EncodeCertPEM(signingCert)
	caKey, err := MarshalPrivateKeyToPEM(signingKey)
	if err != nil {
		log.Fatalf("Failed to marshal key %v", err)
	}

	key, err := NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to create private key for %v", err)
	}

	signedCert, err := NewSignedCert(
		&Config{
			CommonName: names[0],
			AltNames: AltNames{
				DNSNames: names,
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		key, signingCert, signingKey,
	)

	if err != nil {
		log.Fatalf("Failed to create cert%v", err)
	}

	tlsCert := EncodeCertPEM(signedCert)
	tlsKey, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		log.Fatalf("Failed to marshal key %v", err)
	}

	return &SelfSignedCert{
		Signer: Signer{
			CAKey:  caKey,
			CACert: caCert,
		},
		TLSCert: tlsCert,
		TLSKey:  tlsKey,
	}

}

// UpdateTLS uses the same signing certificate to issue a new tls certificate
func (s *SelfSignedCert) UpdateTLS() error {

	signingCert, err := x509Cert(s.CACert)
	if err != nil {
		return err
	}
	signingKey, err := rsaPrivateKey(s.CAKey)
	if err != nil {
		return err
	}

	// Extract the dns names to make this a minimal update
	oldTLSCert, err := x509Cert(s.TLSCert)
	if err != nil {
		return err
	}
	names := oldTLSCert.DNSNames

	key, err := NewPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to create private key for %v", err)
	}

	signedCert, err := NewSignedCert(
		&Config{
			CommonName: names[0],
			AltNames: AltNames{
				DNSNames: names,
			},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		key, signingCert, signingKey,
	)
	if err != nil {
		return fmt.Errorf("failed to create cert%v", err)
	}

	tlsCert := EncodeCertPEM(signedCert)
	tlsKey, err := MarshalPrivateKeyToPEM(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key %v", err)
	}

	s.TLSCert = tlsCert
	s.TLSKey = tlsKey

	return nil

}
