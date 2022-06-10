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

const(
	expiryHeaderKey      = "io.cncf.notary.expiry"
	signingTimeHeaderKey = "io.cncf.notary.signingTime"
	critHeaderKey        = "crit"
	algHeaderKey         = "alg"
	ctyHeaderKey		 = "cty"
)


// JWS represents the JWS-JSON envelope
type JWS struct {
	internalEnv jwsInternalEnvelope
}

func newJWSEnvelopeFromBytes(envelopeBytes []byte) (JWS, error) {
	jwsInternal, err := newJwsInternalEnvelopeFromBytes(envelopeBytes)
	if err != nil {
		return JWS{}, err
	}

	return JWS{ internalEnv: jwsInternal }, nil
}

func newJWSEnvelope() JWS {
	return JWS{internalEnv: newJwsInternalEnvelope()}
}

func (jws JWS) validateIntegrity() error {
	sigInfo, err := jws.getSignerInfo()
	if err != nil {
		return err
	}

	if valError := validateSignerInfo(sigInfo); valError != nil {
		return valError
	}

	// verify JWT
	compact := strings.Join([]string{jws.internalEnv.Protected, jws.internalEnv.Payload, jws.internalEnv.Signature}, ".")
	return verifyJWT(compact, sigInfo.CertificateChain[0].PublicKey)
}

func (jws JWS) getSignerInfo() (SignerInfo, error) {
	signInfo := SignerInfo{}

	// parse payload
	if payload, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Payload); err != nil {
		return signInfo, err
	} else {
		signInfo.Payload = payload
	}

	// parse protected headers
	if protected, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Protected); err != nil {
		return signInfo, err
	} else {
		var pHeaders map[string]interface{}
		if err = json.Unmarshal(protected, &pHeaders); err != nil {
			return signInfo, err
		}
		if err := populateProtectedHeaders(pHeaders, &signInfo); err !=nil {
			return signInfo, err
		}
	}

	// parse signature
	if sig, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Signature); err != nil {
		return signInfo, err
	} else {
		signInfo.Signature = sig
	}

	// parse headers
	certs := make([]x509.Certificate, 0)
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
	crit, err := getAndValidateCriticalHeaders(pHeaders)
	if err != nil {
		return err
	}
	if err :=populateAlg(pHeaders, &signInfo.SignatureAlgorithm); err != nil {
		return err
	}
	populateString(pHeaders, ctyHeaderKey, &signInfo.PayloadContentType)
	if err := populateTime(pHeaders, signingTimeHeaderKey, &signInfo.SignedAttributes.SigningTime); err != nil {
		return err
	}
	if err := populateTime(pHeaders, expiryHeaderKey, &signInfo.SignedAttributes.Expiry); err != nil {
		return err
	}

	// This should be last entry and populates crit and other protected headers
	populateExtendedAttributes(pHeaders, crit, &signInfo.SignedAttributes.ExtendedAttributes)
	return nil
}

func populateString(data map[string]interface{}, s string, holder *string) {
	if val, ok := data[s]; ok {
		*holder = val.(string)
		delete(data, s)
	}
}

func populateAlg(data map[string]interface{}, holder *SignatureAlgorithm) error {
	if val, ok := data["alg"]; ok {
		if sigAlgo , err := getAlgo(val.(string)); err != nil {
			return err
		} else {
			*holder = sigAlgo
			delete(data, "alg")
		}
	}
	return nil
}

func populateTime(data map[string]interface{}, s string, holder *time.Time) error {
	if val, ok := data[s]; ok {
		if value, err := time.Parse(time.RFC3339, val.(string)); err != nil {
			return &MalformedSignatureError{msg: fmt.Sprintf("Failed to parse time for %s attribute, it's not in RFC3339 format", s)}
		} else {
			*holder = value
			delete(data, s)
		}
	}
	return nil
}

// TODO: verify crit values to add signing time etc
func populateExtendedAttributes(data map[string]interface{}, critical []string, holder *[]Attributes) error {
	extendedAttr := make([]Attributes, 0)
	for _, val := range critical {
		extendedAttr = append(extendedAttr, Attributes{
			Key:      val,
			Critical: true,
			Value:    data[val],
		})
		delete(data, val)
	}
	delete(data, critHeaderKey)

	for key, val := range data {
		extendedAttr = append(extendedAttr, Attributes{
			Key:      key,
			Critical: false,
			Value:    val,
		})
	}

	*holder = extendedAttr
	return nil
}

func getAndValidateCriticalHeaders(pHeaders map[string]interface{}) ([]string, error) {
	// using map for performance and that's the reason all values are bool true
	headersMarkedCrit := map[string]bool {signingTimeHeaderKey : true}
	if _, ok := pHeaders[expiryHeaderKey]; ok {
		headersMarkedCrit[expiryHeaderKey] = true
	}

	crit := make([]string, 0)
	if val, ok := pHeaders[critHeaderKey]; ok {
		critical := reflect.ValueOf(val)
		for i := 0; i < critical.Len(); i++ {
			var val = critical.Index(i).Interface().(string)
			if _, ok := headersMarkedCrit[val]; ok {
				delete(headersMarkedCrit, val)
			} else {
				crit = append(crit, val)
			}
		}

		if len(headersMarkedCrit) !=0 {
			// This is not taken care by VerifySignerInfo method
			return crit, &MalformedSignatureError{"Required headers not marked critical" }
		}
		return crit, nil
	} else {
		// This is not taken care by VerifySignerInfo method
		return crit, &MalformedSignatureError{"Missing `crit` header."}
	}
}

func getSignedAttrs(req SignRequest, method jwt.SigningMethod) map[string]interface{} {
	attrs := make(map[string]interface{})
	attrs[algHeaderKey] = method.Alg()
	attrs[signingTimeHeaderKey] = req.SigningTime.Format(time.RFC3339)
	var crit = []string{signingTimeHeaderKey}
	if !req.Expiry.IsZero() {
		attrs[expiryHeaderKey] = req.Expiry.Format(time.RFC3339)
		crit = append(crit, expiryHeaderKey)
	}
	attrs[ctyHeaderKey] = req.PayloadContentType

	for _, elm := range req.ExtendedSignedAttrs {
		attrs[elm.Key] = elm.Value
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
	}

	attrs[critHeaderKey] = crit
	return attrs
}

func (jws JWS) signPayload(req SignRequest) ([]byte, error) {
	leafPublicKey := req.CertificateChain[0].PublicKey
	m := make(map[string]interface{})
	if err := json.Unmarshal(req.Payload, &m); err != nil {
		return []byte{}, err
	}
	signingMethod, _ := getSigningMethod(leafPublicKey)
	signedAttrs := getSignedAttrs(req, signingMethod)
	compact, _ := signJWT(m, signedAttrs, signingMethod, req.SignatureProvider)

	return generateJws(compact, req)
}

// ***********************************************************************
// JWS-JSON specific code
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

	// SigningAgent used for signing
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

func getAlgo(alg string) (SignatureAlgorithm, error) {
	switch alg {
	case "PS256":
		return RSASSA_PSS_SHA_256, nil
	case "PS384":
		return RSASSA_PSS_SHA_384, nil
	case "PS512":
		return RSASSA_PSS_SHA_512, nil
	case "ES256":
		return ECDSA_SHA_256, nil
	case "ES384":
		return ECDSA_SHA_384, nil
	case "ES512":
		return ECDSA_SHA_512, nil
	}

	return RSASSA_PSS_SHA_512, &SignatureAlgoNotSupportedError{alg: alg}
}

// ***********************************************************************
// JWT specific code
// ***********************************************************************
// signJWT signs the given payload and headers using the given signing method and signature provider
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

// verifyJWT verifies the JWT token against the specified verification key
func verifyJWT(tokenString string, key crypto.PublicKey) error {
	signingMethod, _ := getSigningMethod(key)
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

// SigningMethodForSign It's only used during signature generation operation. It's required by JWT library we are using
type SigningMethodForSign struct {
	algo        string
	sigProvider SignatureProvider
}

func (s SigningMethodForSign) Verify(_, _ string, _ interface{}) error {
	return &UnsupportedOperationError{}
}

func (s SigningMethodForSign) Sign(signingString string, _ interface{}) (string, error) {
	if seg, err := s.sigProvider.Sign([]byte(signingString)); err != nil {
		return "", err
	} else {
		return base64.RawURLEncoding.EncodeToString(seg), nil
	}

}

func (s SigningMethodForSign) Alg() string {
	return s.algo
}

// getSigningMethod picks up a recommended algorithm for given public keys.
// It's only used during signature verification operation.
func getSigningMethod(key interface{}) (jwt.SigningMethod, error) {
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
			return nil, &UnSupportedSigningKeyError{keyType : "rsa"}
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
			return nil, &UnSupportedSigningKeyError{keyType : "ecdsa"}
		}
	}
	return nil, &UnSupportedSigningKeyError{}
}