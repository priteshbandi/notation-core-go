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
	sigInfo, err := jws.getSignerInfo()
	if err != nil {
		return err
	}

	if valError := validate(sigInfo); valError != nil {
		return valError
	}

	leafPublicKey := sigInfo.CertificateChain[0].PublicKey

	// verify JWT
	compact := strings.Join([]string{jws.internalEnv.protected, jws.internalEnv.payload, jws.internalEnv.signature}, ".")
	return verifyJWT(compact, leafPublicKey)
}

func (jws JWS) getSignerInfo() (SignerInfo, error) {
	signInfo := SignerInfo{}
	if payload, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.payload); err != nil {
		return signInfo, err
	} else {
		signInfo.Payload = payload
	}

	protected, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.protected)
	if err != nil {
		return signInfo, err
	}

	var pHeaders map[string]interface{}
	if err = json.Unmarshal(protected, &pHeaders); err != nil {
		return signInfo, err
	}
	populateProtectedHeaders(pHeaders, &signInfo)

	// unsigned attrs
	if sig, error := base64.RawURLEncoding.DecodeString(jws.internalEnv.signature); err != nil {
		return signInfo, error
	} else {
		signInfo.Signature = sig
	}

	certs := make([]x509.Certificate, 0, len(jws.internalEnv.header.certChain))
	for _, certBytes := range jws.internalEnv.header.certChain {
		if cert, err := x509.ParseCertificate(certBytes); err != nil {
			return signInfo, err
		} else {
			certs = append(certs, *cert)
		}
	}
	signInfo.CertificateChain = certs

	signInfo.UnsignedAttributes.SigningAgent = jws.internalEnv.header.signingAgent

	signInfo.TimestampSignature = jws.internalEnv.header.timestampSignature

	return signInfo, nil
}

func populateProtectedHeaders(pHeaders map[string]interface{}, signInfo *SignerInfo) error {
	populateString(pHeaders, "cty", &signInfo.PayloadContentType)
	if err := populateTime(pHeaders, "io.cncf.notary.signingTime", &signInfo.SignedAttributes.SigningTime); err != nil {
		return err
	}
	if err := populateTime(pHeaders, "io.cncf.notary.expiry", &signInfo.SignedAttributes.Expiry); err != nil {
		return err
	}
	populateExtendedAttributes(pHeaders, &signInfo.SignedAttributes.ExtendedAttributes)

	return nil
}

func populateString(data map[string]interface{}, s string, holder *string) {
	if val, ok := data[s]; ok {
		*holder = val.(string)
		delete(data, s)
	}
}

func populateTime(data map[string]interface{}, s string, holder *time.Time) error {
	if val, ok := data[s]; ok {
		if value, err := time.Parse(time.RFC3339, val.(string)); err != nil {
			return &MalformedSignatureError{msg: "Failed to parse time, it's not in RFC3339 format"}
		} else {
			*holder = value
			delete(data, s)
		}
	}
	return nil
}

func populateExtendedAttributes(data map[string]interface{}, holder *[]Attributes) {
	extendedAttr := make([]Attributes, len(data))
	if val, ok := data["crit"]; ok {
		delete(data, "crit")
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
	leafPublicKey := req.CertificateChain[0].PublicKey
	m := make(map[string]interface{})
	if err := json.Unmarshal(req.Payload, &m); err != nil {

	}
	signedAttrs := getSignedAttrs(req)
	compact, _ := signJWT(m, signedAttrs, leafPublicKey, req.SignatureProvider)

	return generateJws(compact, req)
}

func getSignedAttrs(req SignRequest) map[string]interface{} {
	attrs := make(map[string]interface{})
	attrs["io.cncf.notary.signingTime"] = req.SigningTime.String()
	if !req.Expiry.IsZero() {
		attrs["io.cncf.notary.expiry"] = req.Expiry.String()
	}
	attrs["cty"] = req.PayloadContentType
	// req.SignatureAlgorithm
	crit := make([]string, len(req.ExtendedSignedAttrs))
	for _, elm := range req.ExtendedSignedAttrs {
		attrs[elm.Key] = elm.Value
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
	}
	return nil
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
	payload string `json:"payload"`

	// jwsProtectedHeader Base64URL-encoded.
	protected string `json:"protected"`

	// Signature metadata that is not integrity protected
	header jwsUnprotectedHeader `json:"header"`

	// Base64URL-encoded signature.
	signature string `json:"signature"`
}

type jwsUnprotectedHeader struct {
	// RFC3161 time stamp token Base64-encoded.
	timestampSignature []byte `json:"io.cncf.notary.timestampSignature,omitempty"`

	// List of X.509 Base64-DER-encoded certificates
	// as defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
	certChain [][]byte `json:"x5c"`

	signingAgent string `json:"io.cncf.notary.signingAgent"`
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
func signJWT(payload map[string]interface{}, headers map[string]interface{}, key crypto.PublicKey, sigPro SignatureProvider) (string, error) {
	signingMethod, _ := signingMethodFromKey(key)
	var claims jwt.MapClaims = payload
	token := &jwt.Token{
		Header: headers,
		Claims: claims,
	}

	token.Method = SigningMethodForSign{algo: signingMethod.Alg(), sigProvider: sigPro}
	compact, err := token.SignedString("DummyNotUsed")
	if err != nil {
		return "", err
	}
	return compact, nil
}

func generateJws(compact string, req SignRequest) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid compact serialization")
	}

	rawCerts := make([][]byte, len(req.CertificateChain))
	for i, cert := range req.CertificateChain {
		rawCerts[i] = cert.Raw
	}

	j := jwsInternalEnvelope{
		protected: parts[0],
		payload:   parts[1],
		signature: parts[2],
		header: jwsUnprotectedHeader{
			certChain:    rawCerts,
			signingAgent: req.SigningAgent,
		},
	}

	return json.Marshal(j)
}

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

// SigningMethodForSign can only be used for signing tokens.
type SigningMethodForSign struct {
	algo        string
	sigProvider SignatureProvider
}

func (s SigningMethodForSign) Verify(signingString, signature string, key interface{}) error {
	return &UnsupportedOperationError{}
}

func (s SigningMethodForSign) Sign(signingString string, key interface{}) (string, error) {
	if seg, err := s.sigProvider.sign([]byte(signingString)); err == nil {
		return base64.RawURLEncoding.EncodeToString(seg), nil
	} else {
		return "", err
	}

}

func (s SigningMethodForSign) Alg() string {
	return s.algo
}

type Claims interface {
	Valid() error
}

type CustomClaims struct{}
