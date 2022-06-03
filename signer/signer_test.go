package signer

import (
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

func TestSignWorkflow(t *testing.T) {
	signatureEnvelope, _ := NewSignatureEnvelopeFromBytes([]byte("VerifyMe!"), JWS_JSON_MEDIA_TYPE)
	err := signatureEnvelope.Verify(x509.CertPool{})
	if err != nil {
		t.Error("Signature Verification Failed.")
	}
}

func TestVerifyWorkflow(t *testing.T) {

}

func TestGetSignInfoWithVerifyWorkflow(t *testing.T) {
	signatureEnvelope, _ := NewSignatureEnvelopeFromBytes([]byte("VerifyMe!"), JWS_JSON_MEDIA_TYPE)
	err := signatureEnvelope.Verify(x509.CertPool{})
	if err != nil {
		t.Error("Signature Verification Failed.")
	}
	signerInfo, signerInfoErr := signatureEnvelope.GetSignerInfo()
	if signerInfoErr != nil {
		t.Error("Failed to get SignerInfo.")
	}

	// TODO Add validation on values of signerInfo
	fmt.Print("Use signer info", signerInfo)
}

func TestGetSignInfoWithoutVerifyWorkflow(t *testing.T) {
	signatureEnvelope, _ := NewSignatureEnvelopeFromBytes([]byte("VerifyMe!"), JWS_JSON_MEDIA_TYPE)
	signerInfo, signerInfoErr := signatureEnvelope.GetSignerInfo()
	if signerInfoErr != nil {
		t.Error("Failed to get SignerInfo.")
	}

	// TODO Add validation on values of signerInfo
	fmt.Print("Use signer info", signerInfo)
}

func TestSignAndVerifyWorkflow(t *testing.T) {
	req := SignRequest{
		Payload:            []byte{},
		PayloadContentType: "",
		CertificateChain:   *x509.NewCertPool(),
		SignatureAlgorithm: RSASSA_PSS_SHA_384,
		SigningTime:        time.Now(),
		Expiry:             time.Now().Add(time.Hour),
		SigningAgent:       "dummyAgent/1.0.0",
	}

	signatureEnvelope, _ := NewSignatureEnvelope(JWS_JSON_MEDIA_TYPE)
	signedEnv, err := signatureEnvelope.Sign(req)
	if err != nil {
		t.Error("Failed to sign.")
	}

	// TODO Check signed envelope is expected one
	fmt.Print("Signed Envelope", signedEnv)
}
