package signer

import (
	"crypto/x509"
	"errors"
	"github.com/notaryproject/notation-core-go/internal/testhelper"
	"testing"
)

func TestNewJWSEnvelope(t *testing.T) {
	newJWSEnvelope()
}

func TestNewJWSEnvelopeFromBytes(t *testing.T) {
	t.Run("newJWSEnvelopeFromBytes", func(t *testing.T) {
		if _, err := newJWSEnvelopeFromBytes([]byte(TEST_VALID_SIG)); err != nil {
			t.Errorf("Error found")
		}
	})

	t.Run("newJWSEnvelopeFromBytes Error", func(t *testing.T) {
		if _, err := newJWSEnvelopeFromBytes([]byte("Malformed")); err == nil {
			t.Errorf("Expected error but not found")
		}
	})
}

func TestValidateIntegrity(t *testing.T) {
	t.Run("with newJWSEnvelope() returns error", func(t *testing.T) {
		env := newJWSEnvelope()
		err := env.validateIntegrity()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but not found")
		}
	})

	t.Run("with NewJWSEnvelopeFromBytes works", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte(TEST_VALID_SIG))
		err := env.validateIntegrity()
		if err != nil {
			t.Errorf("validateIntegrity(). Error = %s", err)
		}
	})

	t.Run("with invalid base64 bytes sig envelope returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"Hi!\",\"Protected\":\"Hi\",\"Header\":{},\"Signature\":\"Hi!\"}"))
		if err := env.validateIntegrity(); err == nil {
			t.Errorf("Expected error but not found")
		}
	})

	t.Run("with incomplete sig envelope returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiXSwiaW8uY25jZi5ub3Rhcnkuc2luaW5nVGltZSI6IjIwMDYtMDEtMDJUMTU6MDQ6MDVaIn0\",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if err := env.validateIntegrity(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected MalformedSignatureError but not found")
		}
	})
}

func TestGetSignerInfo(t *testing.T) {
	t.Run("with newJWSEnvelope() before sign returns error", func(t *testing.T) {
		env := newJWSEnvelope()
		_, err := env.getSignerInfo()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but not found")
		}
	})

	t.Run("with newJWSEnvelope() after sign sign works", func(t *testing.T) {
		env := newJWSEnvelope()
		_, err := env.getSignerInfo()
		env.signPayload(getSignRequest())
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})

	t.Run("with NewJWSEnvelopeFromBytes works", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte(TEST_VALID_SIG))
		_, err := env.getSignerInfo()
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})

	t.Run("with invalid base64 bytes sig envelope returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"Hi!\",\"Protected\":\"Hi\",\"Header\":{},\"Signature\":\"Hi!\"}"))
		if _, err := env.getSignerInfo(); err == nil {
			t.Errorf("Expected error but not found")
		}
	})

	t.Run("with invalid singing time returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiXSwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDA2LS0wMlQxNTowNDowNVoifQ\"" +
			",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if _, err := env.getSignerInfo();  !(err !=nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected error but not found")
		}
	})

	t.Run("with missing crit header returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6Im9sYWYiLCJhdWQiOiJhdWRyZXkiLCJpYXQiOjE2NTQ1ODYyODIsImV4cCI6MTY1NDU4Njg4Mn0\"" +
			",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if _, err := env.getSignerInfo();  !(err !=nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected error but not found")
		}
	})

	t.Run("with malformed alg header returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJhbGciOjEzLCJjcml0IjpbImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIl0sImlvLmNuY2Yubm90YXJ5LnNpbmluZ1RpbWUiOiIyMDA2LTAxLTAyVDE1OjA0OjA1WiJ9\"" +
			",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if _, err := env.getSignerInfo();  !(err !=nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected error but not found")
		}
	})
}

func TestSignPayload(t *testing.T) {
	t.Run("with newJWSEnvelope() works", func(t *testing.T) {
		env := newJWSEnvelope()
		req := getSignRequest()
		_, err := env.signPayload(req)
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})

	t.Run("with unsupported certificate returns error", func(t *testing.T) {
		env := newJWSEnvelope()
		req := getSignRequest()
		req.CertificateChain = []x509.Certificate{*testhelper.GetUnsupportedCertificate().Cert}
		if _, err := env.signPayload(req); !(err !=nil && errors.As(err, new(UnSupportedSigningKeyError))) {
			t.Errorf("Expected UnSupportedSigningKeyError but not found")
		}
	})

}
