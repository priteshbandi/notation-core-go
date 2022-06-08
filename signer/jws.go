package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	JWS_JSON_MEDIA_TYPE SignatureMediaType = "application/jose+json"
)

type JWS struct {
	internalEnv jwsInternalEnvelope
}

func newJWSEnvelopeFromBytes(envelopeBytes []byte) (JWS, error) {
	jwsInternal, err := NewJwsInternalEnvelope(envelopeBytes)
	if err != nil {
		fmt.Println("Inside newJWSEnvelopeFromBytes")
		return JWS{}, err
	}

	return JWS{
		internalEnv: jwsInternal,
	}, nil
}

func newJWSEnvelope() JWS {
	return JWS{}
}

func (jws JWS) validateIntegrity() error {
	fmt.Println("Inside validateIntegrity")
	sigInfo, _ := jws.getSignerInfo()
	leafPublicKey := sigInfo.CertificateChain[0].PublicKey

	// verify JWT
	compact := strings.Join([]string{jws.internalEnv.Protected, jws.internalEnv.Payload, jws.internalEnv.Signature}, ".")
	verifyJWT(compact, leafPublicKey)
	return nil
}

func (jws JWS) getSignerInfo() (SignerInfo, error) {
	fmt.Println("Inside getSignerInfo")
	signInfo := SignerInfo{}
	payload, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Payload)
	if err != nil {
		return signInfo, err
	}
	signInfo.Payload = payload

	protected, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Protected)
	if err != nil {
		return signInfo, err
	}
	var pHeaders map[string]interface{}
	err = json.Unmarshal(protected, &pHeaders)
	if err != nil {
		return signInfo, err
	}

	populateProtectedHeaders(pHeaders, &signInfo)

	// unsigned attrs
	sig, error := base64.RawURLEncoding.DecodeString(jws.internalEnv.Signature)
	if error != nil {
		return signInfo, error
	}
	signInfo.Signature = sig

	certs := make([]x509.Certificate, 0, len(jws.internalEnv.Header.CertChain))
	for _, certBytes := range jws.internalEnv.Header.CertChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return signInfo, err
		}
		certs = append(certs, *cert)
	}
	signInfo.CertificateChain = certs

	signInfo.UnsignedAttributes.SigningAgent = jws.internalEnv.Header.SigningAgent

	signInfo.TimestampSignature = jws.internalEnv.Header.TimestampSignature

	return signInfo, nil
}

func populateProtectedHeaders(pHeaders map[string]interface{}, signInfo *SignerInfo) {
	populateString(pHeaders, "cty", &signInfo.PayloadContentType)
	populateTime(pHeaders, "io.cncf.notary.signingTime", &signInfo.SignedAttributes.SigningTime)
	populateTime(pHeaders, "io.cncf.notary.expiry", &signInfo.SignedAttributes.Expiry)
	populateExtendedAttributes(pHeaders, &signInfo.SignedAttributes.ExtendedAttributes)
}

func populateString(data map[string]interface{}, s string, holder *string) {
	if val, ok := data[s]; ok {
		*holder = val.(string)
		delete(data, s)
	}
}

func populateTime(data map[string]interface{}, s string, holder *time.Time) {
	if val, ok := data[s]; ok {
		value, err := time.Parse(time.RFC3339, val.(string))
		if err != nil {
			fmt.Println("face")
		}
		*holder = value
		delete(data, s)
	}
}

func populateExtendedAttributes(data map[string]interface{}, holder *[]Attributes) {
	extendedAttr := make([]Attributes, len(data))
	if val, ok := data["crit"]; ok {
		delete(data, "crit")
		fmt.Println(val)
		s := reflect.ValueOf(val)
		for i := 0; i < s.Len(); i++ {
			var val string = s.Index(i).Interface().(string)
			extendedAttr[i] = Attributes{
				Key:      val,
				Critical: true,
				Value:    data[val],
			}
			delete(data, val)
		}
	}

	*holder = extendedAttr

}

func (jws JWS) signPayload(req SignRequest) ([]byte, error) {
	fmt.Println("Inside signPayload")
	// construct jws local representation
	// call byteSigner
	// stuff the signature inside local represntation
	// return bytes.
	return []byte{}, nil
}

// ***********************************************************************
// JWS-JSON specifc implementation
// ***********************************************************************
const (
	// MediaTypeJWSEnvelope describes the media type of the JWS envelope.
	MediaTypeJWSEnvelope = "application/vnd.cncf.notary.v2.jws.v1"
)

// JWSEnvelope is the final signature envelope.
type jwsInternalEnvelope struct {
	// JWSPayload Base64URL-encoded.
	Payload string `json:"payload"`

	// jwsProtectedHeader Base64URL-encoded.
	Protected string `json:"protected"`

	// Signature metadata that is not integrity protected
	Header JWSUnprotectedHeader `json:"header"`

	// Base64URL-encoded signature.
	Signature string `json:"signature"`
}

type JWSUnprotectedHeader struct {
	// RFC3161 time stamp token Base64-encoded.
	TimestampSignature []byte `json:"io.cncf.notary.timestampSignature,omitempty"`

	// List of X.509 Base64-DER-encoded certificates
	// as defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
	CertChain [][]byte `json:"x5c"`

	SigningAgent string `json:"io.cncf.notary.signingAgent"`
}

func NewJwsInternalEnvelope(b []byte) (jwsInternalEnvelope, error) {
	jws := jwsInternalEnvelope{}
	if err := json.Unmarshal(b, &jws); err != nil {
		return jws, err
	}
	return jws, nil
}

// ***********************************************************************
// JWT specifc implementation
// ***********************************************************************
// verifyJWT verifies the JWT token against the specified verification key, and
// returns notation claim.
func verifyJWT(tokenString string, key crypto.PublicKey) error {
	signingMethod, _ := signingMethodFromKey(key)
	// parse and verify token
	parser := &jwt.Parser{
		ValidMethods:         []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"},
		UseJSONNumber:        true,
		SkipClaimsValidation: true,
	}

	if _, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v: require %v", t.Method.Alg(), signingMethod.Alg())
		}

		// override default signing method with key-specific method
		t.Method = signingMethod
		return key, nil
	}); err != nil {
		return err
	}
	return nil
}

// SigningMethodFromKey picks up a recommended algorithm for private and public keys.
// Reference: RFC 7518 3.1 "alg" (Algorithm) Header Parameter Values for JWS.
func signingMethodFromKey(key interface{}) (jwt.SigningMethod, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return jwt.SigningMethodPS256, nil
		case 384:
			return jwt.SigningMethodPS384, nil
		case 512:
			return jwt.SigningMethodPS512, nil
		default:
			return jwt.SigningMethodPS256, nil
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case jwt.SigningMethodES256.CurveBits:
			return jwt.SigningMethodES256, nil
		case jwt.SigningMethodES384.CurveBits:
			return jwt.SigningMethodES384, nil
		case jwt.SigningMethodES512.CurveBits:
			return jwt.SigningMethodES512, nil
		default:
			return nil, errors.New("ecdsa key not recognized")
		}
	}
	return nil, errors.New("key not recognized")
}
