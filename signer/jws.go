package signer

import "fmt"

const (
	JWS_JSON_MEDIA_TYPE SignatureMediaType = "application/jose+json"
)

type JWS struct {
}

func newJWSEnvelopeFromBytes(envelopeBytes []byte) JWS {
	return JWS{}
}

func newJWSEnvelope() JWS {
	return JWS{}
}

func (jws JWS) validateIntegrity() error {
	fmt.Println("Inside validateIntegrity")
	return nil
}

func (jws JWS) getSignerInfo() (SignerInfo, error) {
	return SignerInfo{}, nil
}

func (jws JWS) signPayload(req SignRequest) ([]byte, error) {
	fmt.Println("Inside signPayload")
	// construct jws local representation
	// call byteSigner
	// stuff the signature inside local represntation
	// return bytes.
	return []byte{}, nil
}
