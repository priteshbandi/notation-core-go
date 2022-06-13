package signer

import (
	"errors"
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
			t.Errorf("validateIntegrity. Error: %s", err)
		}
	})
}

func TestGetSignerInfo(t *testing.T) {

}

func TestSignPayload(t *testing.T) {

}
