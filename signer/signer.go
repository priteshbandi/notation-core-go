package signer

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

type SignatureMediaType string

// SignatureAlgorithm lists supported Signature algorithms.
type SignatureAlgorithm string

const (
	RSASSA_PSS_SHA_256 SignatureAlgorithm = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384 SignatureAlgorithm = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512 SignatureAlgorithm = "RSASSA_PSS_SHA_512"
	ECDSA_SHA_256      SignatureAlgorithm = "ECDSA_SHA_256"
	ECDSA_SHA_384      SignatureAlgorithm = "ECDSA_SHA_384"
	ECDSA_SHA_512      SignatureAlgorithm = "ECDSA_SHA_512"
)

// SignerInfo represents a parsed Signature envelope and agnostic to Signature envelope format.
type SignerInfo struct {
	Payload            []byte
	PayloadContentType string
	SignedAttributes   SignedAttributes
	UnsignedAttributes UnsignedAttributes
	SignatureAlgorithm SignatureAlgorithm
	CertificateChain   []x509.Certificate
	Signature          []byte
	TimestampSignature []byte
}

// SignedAttributes represents signed metadata in the Signature envelope
type SignedAttributes struct {
	SigningTime        time.Time // library will take care critical/presence
	Expiry             time.Time // library will take care critical/presence
	ExtendedAttributes []Attributes
}

// UnsignedAttributes represents unsigned metadata in the Signature envelope
type UnsignedAttributes struct {
	SigningAgent string
}

// SignRequest is used to generate Signature.
type SignRequest struct {
	Payload             []byte
	PayloadContentType  string
	CertificateChain    []x509.Certificate
	SignatureProvider   SignatureProvider
	SigningTime         time.Time // library will take care critical/presence
	Expiry              time.Time // library will take care critical/presence
	ExtendedSignedAttrs []Attributes
	SigningAgent        string
}

type Attributes struct {
	Key      string
	Critical bool
	Value    interface{}
}

// SignatureProvider is used to sign bytes generated after creating Signature envelope.
type SignatureProvider interface {
	Sign([]byte) ([]byte, error)
}

type SignatureEnvelope struct {
	rawSignatureEnvelope []byte
	internalEnvelope     internalSignatureEnvelope
}

// Contains set of common methods that every Signature envelope format must implement.
type internalSignatureEnvelope interface {
	// validateIntegrity validates the integrity of given Signature envelope.
	validateIntegrity() error
	// getSignerInfo returns the information stored in the Signature envelope and doesn't perform integrity verification.
	getSignerInfo() (SignerInfo, error)
	// signPayload created Signature envelope.
	signPayload(SignRequest) ([]byte, error)
}

// Verify performs integrity validation and validates that cert-chain stored in Signature leads to given set of trusted root.
func (s SignatureEnvelope) Verify(certs []x509.Certificate) (x509.Certificate, error) {
	if len(s.rawSignatureEnvelope) == 0 {
		return x509.Certificate{}, &SignatureNotFoundError{}
	}

	integrityError := s.internalEnvelope.validateIntegrity()
	if integrityError != nil {
		return x509.Certificate{}, integrityError
	}

	singerInfo, singerInfoErr := s.internalEnvelope.getSignerInfo()
	if singerInfoErr != nil {
		return x509.Certificate{}, integrityError
	}

	certChain := singerInfo.CertificateChain
	//TODO Implement validation on cert chain
	fmt.Println("Yet to implement cert-chain validation for", certChain)

	//TODO Implement truststore validation
	fmt.Println("Yet to implement truststore validation")
	return verifySigner(certChain, certs)
}

// Sign generates Signature using given SignRequest.
func (s SignatureEnvelope) Sign(req SignRequest) ([]byte, error) {
	return s.internalEnvelope.signPayload(req)
}

// GetSignerInfo returns information about the Signature envelope
func (s SignatureEnvelope) GetSignerInfo() (SignerInfo, error) {
	return s.internalEnvelope.getSignerInfo()
}

func validate(info SignerInfo) error {
	if len(info.Payload) == 0 {
		return &MalformedSignatureError{msg: "Payload not present"}
	}

	if len(info.CertificateChain) == 0 {
		return &MalformedSignatureError{msg: "Certificate chain not present or is empty"}
	}

	if len(info.Signature) == 0 {
		return &MalformedSignatureError{msg: "Signature not present or is empty"}
	}

	signTime := info.SignedAttributes.SigningTime
	if signTime.IsZero() {
		return &MalformedSignatureError{msg: "Singing time not present"}
	}

	expTime := info.SignedAttributes.Expiry
	if !expTime.IsZero() {
		if expTime.Before(signTime) || expTime.Equal(signTime) {
			return &MalformedSignatureError{msg: "Expiry time cannot be equal or before the signing time"}
		}
	}

	if len(info.PayloadContentType) == 0 {
		return &MalformedSignatureError{msg: "Signature content type not present or is empty"}
	}

	return nil
}

// NewSignatureEnvelopeFromBytes For verify flow
func NewSignatureEnvelopeFromBytes(envelopeBytes []byte, envelopeMediaType SignatureMediaType) (SignatureEnvelope, error) {
	switch envelopeMediaType {
	case JWS_JSON_MEDIA_TYPE:
		internal, err := newJWSEnvelopeFromBytes(envelopeBytes)
		if err != nil {
			return SignatureEnvelope{}, nil
		}
		return SignatureEnvelope{
			rawSignatureEnvelope: envelopeBytes,
			internalEnvelope:     internal,
		}, nil
	default:
		return SignatureEnvelope{}, &UnsupportedSignatureFormatError{mediaType: string(envelopeMediaType)}
	}
}

// NewSignatureEnvelope For signing Flow
func NewSignatureEnvelope(envelopeMediaType SignatureMediaType) (SignatureEnvelope, error) {
	switch envelopeMediaType {
	case JWS_JSON_MEDIA_TYPE:
		return SignatureEnvelope{internalEnvelope: newJWSEnvelope()}, nil
	default:
		return SignatureEnvelope{}, &UnsupportedSignatureFormatError{mediaType: string(envelopeMediaType)}
	}
}

func verifySigner(sigCerts []x509.Certificate, trustedCerts []x509.Certificate) (x509.Certificate, error) {
	// TODO: Validate cert chain (sigCert).

	for _, trust := range trustedCerts {
		for _, sig := range sigCerts {
			if trust.Equal(&sig) {
				return trust, nil
			}
		}
	}
	return x509.Certificate{}, errors.New("hoka")
}
