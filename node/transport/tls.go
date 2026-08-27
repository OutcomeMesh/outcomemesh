package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const ALPN = "outcomemesh/0"

var (
	ErrIdentity        = errors.New("invalid transport identity")
	ErrPeerCertificate = errors.New("invalid peer certificate")
	ErrUnexpectedPeer  = errors.New("unexpected peer identity")
)

type Identity struct {
	privateKey  ed25519.PrivateKey
	certificate tls.Certificate
	id          types.Hash
}

func GenerateIdentity() (Identity, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return NewIdentity(privateKey)
}

func NewIdentity(privateKey ed25519.PrivateKey) (Identity, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Identity{}, ErrIdentity
	}
	cloned := append(ed25519.PrivateKey(nil), privateKey...)
	publicKey := cloned.Public().(ed25519.PublicKey)
	id, err := PeerIDFromPublicKey(publicKey)
	if err != nil {
		return Identity{}, err
	}
	serial := new(big.Int).SetBytes(id[:20])
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.String()},
		NotBefore:             time.Unix(1_577_836_800, 0), // 2020-01-01 UTC
		NotAfter:              time.Unix(4_102_444_800, 0), // 2100-01-01 UTC
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, cloned)
	if err != nil {
		return Identity{}, err
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{encoded},
		PrivateKey:  cloned,
		Leaf:        template,
	}
	return Identity{privateKey: cloned, certificate: certificate, id: id}, nil
}

func (identity Identity) ID() types.Hash { return identity.id }

func (identity Identity) PrivateKey() ed25519.PrivateKey {
	return append(ed25519.PrivateKey(nil), identity.privateKey...)
}

func PeerIDFromPublicKey(publicKey ed25519.PublicKey) (types.Hash, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return types.Hash{}, ErrIdentity
	}
	return types.DomainHash("OMESH/p2p/ed25519/v0", publicKey), nil
}

func ServerTLSConfig(identity Identity) (*tls.Config, error) {
	if identity.id.IsZero() || len(identity.certificate.Certificate) != 1 {
		return nil, ErrIdentity
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{identity.certificate},
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		NextProtos:            []string{ALPN},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verifier(nil),
	}, nil
}

func ClientTLSConfig(identity Identity, expectedPeer *types.Hash) (*tls.Config, error) {
	if identity.id.IsZero() || len(identity.certificate.Certificate) != 1 {
		return nil, ErrIdentity
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{identity.certificate},
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		NextProtos:            []string{ALPN},
		InsecureSkipVerify:    true, // replaced by the public-key verifier below
		VerifyPeerCertificate: verifier(expectedPeer),
	}, nil
}

func Listen(address string, identity Identity) (net.Listener, error) {
	config, err := ServerTLSConfig(identity)
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", address, config)
}

func Dial(ctx context.Context, address string, identity Identity, expectedPeer *types.Hash) (*tls.Conn, types.Hash, error) {
	config, err := ClientTLSConfig(identity, expectedPeer)
	if err != nil {
		return nil, types.Hash{}, err
	}
	dialer := tls.Dialer{Config: config}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, types.Hash{}, err
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		_ = connection.Close()
		return nil, types.Hash{}, ErrPeerCertificate
	}
	id, err := PeerID(tlsConnection)
	if err != nil {
		_ = tlsConnection.Close()
		return nil, types.Hash{}, err
	}
	return tlsConnection, id, nil
}

func PeerID(connection *tls.Conn) (types.Hash, error) {
	state := connection.ConnectionState()
	if !state.HandshakeComplete || state.NegotiatedProtocol != ALPN || len(state.PeerCertificates) != 1 {
		return types.Hash{}, ErrPeerCertificate
	}
	publicKey, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return types.Hash{}, ErrPeerCertificate
	}
	return PeerIDFromPublicKey(publicKey)
}

func verifier(expected *types.Hash) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCertificates [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCertificates) != 1 {
			return ErrPeerCertificate
		}
		certificate, err := x509.ParseCertificate(rawCertificates[0])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPeerCertificate, err)
		}
		if !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) ||
			certificate.SignatureAlgorithm != x509.PureEd25519 ||
			certificate.PublicKeyAlgorithm != x509.Ed25519 {
			return ErrPeerCertificate
		}
		if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
			return fmt.Errorf("%w: %v", ErrPeerCertificate, err)
		}
		now := time.Now()
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return ErrPeerCertificate
		}
		publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok {
			return ErrPeerCertificate
		}
		id, err := PeerIDFromPublicKey(publicKey)
		if err != nil {
			return err
		}
		if expected != nil && id != *expected {
			return ErrUnexpectedPeer
		}
		return nil
	}
}
