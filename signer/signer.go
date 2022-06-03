package signer

import (
	"crypto/x509"
	"fmt"
	"time"
)

type SignatureMediaType string

// List of supported signature algorithms.
type SignatureAlgorithm string

const (
	RSASSA_PSS_SHA_256 SignatureAlgorithm = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384 SignatureAlgorithm = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512 SignatureAlgorithm = "RSASSA_PSS_SHA_512"
	ECDSA_SHA_256      SignatureAlgorithm = "ECDSA_SHA_256"
	ECDSA_SHA_384      SignatureAlgorithm = "ECDSA_SHA_384"
	ECDSA_SHA_512      SignatureAlgorithm = "ECDSA_SHA_512"
)

// SignerInfo reprents an parsed signature envelope and agnostic to signature envelope format.
type SignerInfo struct {
	Payload            []byte
	PayloadContentType string
	SignedAttributes   SignedAttributes
	UnsignedAttributes UnsignedAttributes
	SignatureAlgorithm SignatureAlgorithm
	CertificateChain   x509.CertPool
	Signature          []byte
	TimestampSignature []byte
}

// SignRequest is used to generate signature.
type SignRequest struct {
	Payload            []byte
	PayloadContentType string
	CertificateChain   x509.CertPool
	SignatureAlgorithm SignatureAlgorithm
	SignatureProvider  SignatureProvider
	SigningTime        time.Time // library will take care critical/presence
	Expiry             time.Time // library will take care critical/presence
	SigningAgent       string
}

// SignedAttributes represents signed metadata in the signature envelope
type SignedAttributes struct {
	SigningTime              time.Time // library will take care critical/presence
	Expiry                   time.Time // library will take care critical/presence
	ExtendedSignedAttributes []Attributes
}

// UnsignedAttributes represents unsigned metadata in the signature envelope
type UnsignedAttributes struct {
	SigningAgent string
}

type Attributes struct {
	Key      string
	Critical bool
	Value    interface{}
}

// SignatureProvider is used to sign bytes generated after creating signature envelope.
type SignatureProvider interface {
	sign([]byte) ([]byte, error)
}

type SignatureEnvelope struct {
	rawSignatureEnvelope []byte
	internalEnvelope     internalSignatureEnvelope
}

// Contians set of common methods that every signature envelope format must implement.
type internalSignatureEnvelope interface {
	// validateIntegrity validates the integrity of given signature envelope.
	validateIntegrity() error
	// getSignerInfo returns the information stored in the signature envelope and doesnt performs integrity verification.
	getSignerInfo() (SignerInfo, error)
	// signPayload created signature envelope.
	signPayload(SignRequest) ([]byte, error)
}

// Verify method performs integrety validation and validates that cert-chain stored in signature leads to given set of trusted root.
func (s SignatureEnvelope) Verify(certs x509.CertPool) error {
	if len(s.rawSignatureEnvelope) == 0 {
		return &SignatureNotFoundError{}
	}

	integrityError := s.internalEnvelope.validateIntegrity()
	if integrityError != nil {
		return integrityError
	}

	singerInfo, singerInfoErr := s.internalEnvelope.getSignerInfo()
	if singerInfoErr != nil {
		return integrityError
	}

	certChain := singerInfo.CertificateChain
	//TODO Implement validation on cert chain
	fmt.Println("Yet to implement cert-chain validation for", certChain)

	//TODO Implement truststore validation
	fmt.Println("Yet to implement truststore validation")
	return nil
}

// Sign generates signature using given SignRequest.
func (s SignatureEnvelope) Sign(req SignRequest) ([]byte, error) {
	return s.internalEnvelope.signPayload(req)
}

// Returns information about the signature envelope
func (s SignatureEnvelope) GetSignerInfo() (SignerInfo, error) {
	return s.internalEnvelope.getSignerInfo()
}

// For verify flow
func NewSignatureEnvelopeFromBytes(envelopeBytes []byte, envelopeMediaType SignatureMediaType) (SignatureEnvelope, error) {
	switch envelopeMediaType {
	case JWS_JSON_MEDIA_TYPE:
		return SignatureEnvelope{
			rawSignatureEnvelope: envelopeBytes,
			internalEnvelope:     newJWSEnvelopeFromBytes(envelopeBytes),
		}, nil
	default:
		return SignatureEnvelope{}, &UnsupportedSignatureFormatError{mediaType: string(envelopeMediaType)}
	}
}

// For signing Flow
func NewSignatureEnvelope(envelopeMediaType SignatureMediaType) (SignatureEnvelope, error) {
	switch envelopeMediaType {
	case JWS_JSON_MEDIA_TYPE:
		return SignatureEnvelope{internalEnvelope: newJWSEnvelope()}, nil
	default:
		return SignatureEnvelope{}, &UnsupportedSignatureFormatError{mediaType: string(envelopeMediaType)}
	}
}
