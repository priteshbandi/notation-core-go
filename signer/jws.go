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
	jwsInternal, err := newJwsInternalEnvelopeFromBytes(envelopeBytes)
	if err != nil {
		return JWS{}, err
	}

	return JWS{
		internalEnv: jwsInternal,
	}, nil
}

func newJWSEnvelope() JWS {
	return JWS{internalEnv: newJwsInternalEnvelope()}
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
	compact := strings.Join([]string{jws.internalEnv.Protected, jws.internalEnv.Payload, jws.internalEnv.Signature}, ".")
	return verifyJWT(compact, leafPublicKey)
}

func (jws JWS) getSignerInfo() (SignerInfo, error) {
	signInfo := SignerInfo{}
	if payload, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Payload); err != nil {
		return signInfo, err
	} else {
		signInfo.Payload = payload
	}

	protected, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Protected)
	if err != nil {
		return signInfo, err
	}

	var pHeaders map[string]interface{}
	if err = json.Unmarshal(protected, &pHeaders); err != nil {
		return signInfo, err
	}
	populateProtectedHeaders(pHeaders, &signInfo)

	// unsigned attrs
	if sig, err2 := base64.RawURLEncoding.DecodeString(jws.internalEnv.Signature); err != nil {
		return signInfo, err2
	} else {
		signInfo.Signature = sig
	}

	certs := make([]x509.Certificate, 0, len(jws.internalEnv.Header.CertChain))
	for _, certBytes := range jws.internalEnv.Header.CertChain {
		if cert, err := x509.ParseCertificate(certBytes); err != nil {
			return signInfo, err
		} else {
			certs = append(certs, *cert)
		}
	}
	signInfo.CertificateChain = certs

	signInfo.UnsignedAttributes.SigningAgent = jws.internalEnv.Header.SigningAgent

	signInfo.TimestampSignature = jws.internalEnv.Header.TimestampSignature

	return signInfo, nil
}

func populateProtectedHeaders(pHeaders map[string]interface{}, signInfo *SignerInfo) error {
	populateAlg(pHeaders, &signInfo.SignatureAlgorithm)
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

func populateAlg(data map[string]interface{}, holder *SignatureAlgorithm) {
	if val, ok := data["alg"]; ok {
		*holder = getAlgo(val.(string))
		delete(data, "alg")
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
			var val = s.Index(i).Interface().(string)
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
	signingMethod, _ := signingMethodFromKey(leafPublicKey)
	signedAttrs := getSignedAttrs(req, signingMethod)
	compact, _ := signJWT(m, signedAttrs, signingMethod, req.SignatureProvider)

	return generateJws(compact, req)
}

func getSignedAttrs(req SignRequest, method jwt.SigningMethod) map[string]interface{} {
	attrs := make(map[string]interface{})

	attrs["alg"] = method.Alg()
	attrs["io.cncf.notary.signingTime"] = req.SigningTime.Format(time.RFC3339)
	if !req.Expiry.IsZero() {
		attrs["io.cncf.notary.expiry"] = req.Expiry.Format(time.RFC3339)
	}
	attrs["cty"] = req.PayloadContentType
	// req.SignatureAlgorithm
	var crit []string
	for _, elm := range req.ExtendedSignedAttrs {
		attrs[elm.Key] = elm.Value
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
	}

	attrs["crit"] = crit
	return attrs
}

// ***********************************************************************
// JWS-JSON specific implementation
// ***********************************************************************
const (
	// JWS_PAYLOAD_CONTENT_TYPE describes the media type of the JWS envelope.
	JWS_PAYLOAD_CONTENT_TYPE = "application/vnd.cncf.notary.v2.jws.v1"
)

// JWSEnvelope is the final Signature envelope.
type jwsInternalEnvelope struct {
	// JWSPayload Base64URL-encoded.
	Payload string `json:"Payload"`

	// jwsProtectedHeader Base64URL-encoded.
	Protected string `json:"Protected"`

	// Signature metadata that is not integrity Protected
	Header jwsUnprotectedHeader `json:"Header"`

	// Base64URL-encoded Signature.
	Signature string `json:"Signature"`
}

type jwsUnprotectedHeader struct {
	// RFC3161 time stamp token Base64-encoded.
	TimestampSignature []byte `json:"io.cncf.notary.TimestampSignature,omitempty"`

	// List of X.509 Base64-DER-encoded certificates
	// as defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
	CertChain [][]byte `json:"x5c"`

	SigningAgent string `json:"io.cncf.notary.SigningAgent,omitempty"`
}

func newJwsInternalEnvelopeFromBytes(b []byte) (jwsInternalEnvelope, error) {
	jws := jwsInternalEnvelope{}
	if err := json.Unmarshal(b, &jws); err != nil {
		return jws, err
	}

	return jws, nil
}

func newJwsInternalEnvelope() jwsInternalEnvelope {
	return jwsInternalEnvelope{}
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
		Protected: parts[0],
		Payload:   parts[1],
		Signature: parts[2],
		Header: jwsUnprotectedHeader{
			CertChain:    rawCerts,
			SigningAgent: req.SigningAgent,
		},
	}

	return json.Marshal(j)
}

func getAlgo(alg string) SignatureAlgorithm {
	switch alg {
	case "PS256":
		return RSASSA_PSS_SHA_256
	case "PS384":
		return RSASSA_PSS_SHA_384
	case "PS512":
		return RSASSA_PSS_SHA_512
	case "ES256":
		return ECDSA_SHA_256
	case "ES384":
		return ECDSA_SHA_384
	case "ES512":
		return ECDSA_SHA_512
	}
	return ""
}

// ***********************************************************************
// JWT specific implementation
// ***********************************************************************
func signJWT(payload map[string]interface{}, headers map[string]interface{}, method jwt.SigningMethod, sigPro SignatureProvider) (string, error) {
	var claims jwt.MapClaims = payload
	token := &jwt.Token{
		Header: headers,
		Claims: claims,
	}

	token.Method = SigningMethodForSign{algo: method.Alg(), sigProvider: sigPro}
	compact, err := token.SignedString("DummyNotUsed")
	if err != nil {
		return "", err
	}
	return compact, nil
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

func (s SigningMethodForSign) Verify(_, _ string, _ interface{}) error {
	return &UnsupportedOperationError{}
}

func (s SigningMethodForSign) Sign(signingString string, _ interface{}) (string, error) {
	if seg, err := s.sigProvider.Sign([]byte(signingString)); err == nil {
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
