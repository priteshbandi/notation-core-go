package signer

import (
	"testing"
)

func TestNewJWSEnvelope(t *testing.T) {
	newJWSEnvelope()
}

func TestNewJWSEnvelopeFromBytes(t *testing.T) {
	t.Run("Test NewJWSEnvelopeFromBytes", func(t *testing.T) {
		if _, err := newJWSEnvelopeFromBytes([]byte(TEST_VALID_SIG)); err != nil {
			t.Errorf("Error found")
		}
	})

	t.Run("Test NewJWSEnvelopeFromBytes Error", func(t *testing.T) {
		if _, err := newJWSEnvelopeFromBytes([]byte("Malformed")); err == nil {
			t.Errorf("Expected error but not found")
		}
	})
}

func TestValidateIntegrity(t *testing.T) {
	env := newJWSEnvelope()
	if err := env.validateIntegrity(); err != nil {
		t.Errorf("Error found: %s", err)
	}
}

func TestGetSignerInfo(t *testing.T) {

}

func TestSignPayload(t *testing.T) {

}
