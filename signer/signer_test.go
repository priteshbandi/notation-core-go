package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/notaryproject/notation-core-go/internal/testhelper"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	TEST_PAYLOAD   = "{\n  \"iss\": \"DinoChiesa.github.io\",\n  \"sub\": \"olaf\",\n  \"aud\": \"audrey\",\n  \"iat\": 1654586282,\n  \"exp\": 1654586882\n}"
	TEST_VALID_SIG = "{\"Payload\":\"eyJhdWQiOiJhdWRyZXkiLCJleHAiOjE2NTQ1ODY4ODIsImlhdCI6MTY1NDU4NjI4MiwiaXNzIjoiRGlub0NoaWVzYS5naXRodWIuaW8iLCJzdWIiOiJvbGFmIn0\"," +
		"\"Protected\":\"eyJhbGciOiJQUzUxMiIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiLCJzaWduZWRDcml0S2V5MSJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkudjIuandzLnYxIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjAyMi0wNi0xMlQxODoyNDo1NS0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIjoiMjAyMi0wNi0xMVQxODoyNDo1NS0wNzowMCIsInNpZ25lZENyaXRLZXkxIjoic2lnbmVkVmFsdWUxIiwic2lnbmVkS2V5MSI6InNpZ25lZEtleTIifQ\"," +
		"\"Header\":{" +
		"	\"x5c\":[" +
		"		\"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\"]," +
		"		\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"}," +
		"\"Signature\":\"YjGjKbLFTpaPAyKQoubOCeVNkUH7dGCXboedKcdVRqvrX3YOSm-2134KqCQInyIh9mstOK-IgibMTrFX4nOMfrgZcbPLmnNpuJjmjwQ8cY77mMIOnYWvYtWDR3uiLt7292LbHjviNzNBqdaYClaLH0ASE5CHXQZj8zMfEPkwS_iCV81qHITNfrtpWjRiCNOidLHfCVv-agr7ztGp6AcS3FWy3KnreWQ-cJmCTfU92DpBpeVwf_2Q4h8q_NiNqPf1xWgtzvXgMkbXx8IzuxKRevIld0o9pyIwLL4CSKgRD0eV37K99sA1Cggru4hiV9Orlp-JHlYpkdabBiLmrSeOZNpiq9JySCJDQu76p5C3xwgtbbHheXRTY--C2eTjcUj4g5DIdPgN-GkeFEt6RbHhrWFSVnoI_qBpt7Oz50dnAaON5Os2QY4BSoOlEplNXrSpNpbwTEafquF6PKIJIrIXInUrSHIuk13vqGX2LqrfbFhSGwkY7JertPULrIa1vnZn_gkDpv_D9jRvORz3OgMYU7DdOUan7V74gnyhKJZVJ6LmYj27mLpVn-gEg48eezGpDI7x2b-vtNt6TxVItDsnSjwrlpzHIJrZSj_wOfyed7niOxArcQ_qHd-euUxHL79ZBm5kCdi7AwioUs8Sv0lTrqzgfYoRvcpQ96i8Ql-PwUU\"}\n"
	TEST_INVALID_SIG = "{\"Payload\":\"eyJhdWQiOiJhdWRyZXkiLCJleHAiOjE2NTQ1ODY4ODIsImlhdCI6MTY1NDU4NjI4MiwiaXNzIjoiRGlub0NoaWVzYS5naXRodWIuaW8iLCJzdWIiOiJvbGFmIn0\"," +
		"\"Protected\":\"eyJhbGciOiJQUzUxMiIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiLCJzaWduZWRDcml0S2V5MSJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkudjIuandzLnYxIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjAyMi0wNi0xMlQxODoyNDo1NS0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIjoiMjAyMi0wNi0xMVQxODoyNDo1NS0wNzowMCIsInNpZ25lZENyaXRLZXkxIjoic2lnbmVkVmFsdWUxIiwic2lnbmVkS2V5MSI6InNpZ25lZEtleTIifQ\"," +
		"\"Header\":{" +
		"	\"x5c\":[" +
		"		\"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\"]," +
		"		\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"}," +
		"\"Signature\":\"PAyKQoubOCeVNkUH7dGCXboedKcdVRqvrX3YOSm-2134KqCQInyIh9mstOK-IgibMTrFX4nOMfrgZcbPLmnNpuJjmjwQ8cY77mMIOnYWvYtWDR3uiLt7292LbHjviNzNBqdaYClaLH0ASE5CHXQZj8zMfEPkwS_iCV81qHITNfrtpWjRiCNOidLHfCVv-agr7ztGp6AcS3FWy3KnreWQ-cJmCTfU92DpBpeVwf_2Q4h8q_NiNqPf1xWgtzvXgMkbXx8IzuxKRevIld0o9pyIwLL4CSKgRD0eV37K99sA1Cggru4hiV9Orlp-JHlYpkdabBiLmrSeOZNpiq9JySCJDQu76p5C3xwgtbbHheXRTY--C2eTjcUj4g5DIdPgN-GkeFEt6RbHhrWFSVnoI_qBpt7Oz50dnAaON5Os2QY4BSoOlEplNXrSpNpbwTEafquF6PKIJIrIXInUrSHIuk13vqGX2LqrfbFhSGwkY7JertPULrIa1vnZn_gkDpv_D9jRvORz3OgMYU7DdOUan7V74gnyhKJZVJ6LmYj27mLpVn-gEg48eezGpDI7x2b-vtNt6TxVItDsnSjwrlpzHIJrZSj_wOfyed7niOxArcQ_qHd-euUxHL79ZBm5kCdi7AwioUs8Sv0lTrqzgfYoRvcpQ96i8Ql-PwUU\"}\n"
)

func TestNewSignatureEnvelopeFromBytesError(t *testing.T) {
	_, err := NewSignatureEnvelopeFromBytes([]byte("Malformed"), JWS_JSON_MEDIA_TYPE)
	if !(err != nil && errors.As(err, new(MalformedArgumentError))) {
		t.Errorf("Expected MalformedArgumentError but not found")
	}
}

func TestSign(t *testing.T) {
	env, err := NewSignatureEnvelope(JWS_JSON_MEDIA_TYPE)
	if err != nil {
		t.Fatalf("NewSignatureEnvelope() error = %v", err)
	}

	req := getSignRequest()
	verifySignWithRequest(env, req, t)

	req = getSignRequest()
	req.Expiry = time.Time{}
	verifySignWithRequest(env, req, t)

	req = getSignRequest()
	req.SigningAgent = ""
	verifySignWithRequest(env, req, t)

	req = getSignRequest()
	req.ExtendedSignedAttrs = nil
	verifySignWithRequest(env, req, t)
}

func TestSignErrors(t *testing.T) {
	env, _ := NewSignatureEnvelope(JWS_JSON_MEDIA_TYPE)
	req := getSignRequest()

	t.Run("When Payload is absent", func(t *testing.T) {
		req.Payload = nil
		verifySignErrorWithRequest(env, req, t)
	})
	t.Run("When PayloadContentType is absent", func(t *testing.T) {
		req = getSignRequest()
		req.PayloadContentType = ""
		verifySignErrorWithRequest(env, req, t)
	})
	t.Run("When SigningTime is absent", func(t *testing.T) {
		req = getSignRequest()
		req.SigningTime = time.Time{}
		verifySignErrorWithRequest(env, req, t)
	})
	t.Run("When SignatureProvider is absent", func(t *testing.T) {
		req = getSignRequest()
		req.SignatureProvider = nil
		verifySignErrorWithRequest(env, req, t)
	})
	t.Run("When CertificateChain is absent", func(t *testing.T) {
		req = getSignRequest()
		req.CertificateChain = nil
		verifySignErrorWithRequest(env, req, t)
	})
	t.Run("When expiry is before singing time", func(t *testing.T) {
		req = getSignRequest()
		req.Expiry = req.SigningTime.AddDate(0,0,-1)
		verifySignErrorWithRequest(env, req, t)
	})
}

func TestVerify(t *testing.T) {
	certs := "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"

	var trustedCertsBytes []byte
	for _, element := range strings.Split(certs, ",") {
		certBytes, _ := base64.StdEncoding.DecodeString(element)
		trustedCertsBytes = append(trustedCertsBytes, certBytes...)
	}
	trustedCerts, _ := x509.ParseCertificates(trustedCertsBytes)

	env, err := NewSignatureEnvelopeFromBytes([]byte(TEST_VALID_SIG), JWS_JSON_MEDIA_TYPE)
	if err != nil {
		t.Fatalf("NewSignatureEnvelopeFromBytes() error = %v", err)
	}

	cert, err := env.Verify([]x509.Certificate{*trustedCerts[1]})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !cert.Equal(trustedCerts[1]) {
		t.Fatalf("Expected cert with subject %s but found cert with subject %s", cert.Subject, testhelper.GetRootCertificate().Cert.Subject)
	}

	info, err := env.GetSignerInfo()
	if err != nil {
		t.Fatalf("GetSignerInfo() error = %v", err)
	}

	req := getSignRequest()
	req.SigningTime, err = time.Parse(time.RFC3339, "2022-06-11T18:24:55-07:00")
	req.Expiry = req.SigningTime.AddDate(0, 0, 1)
	req.CertificateChain = []x509.Certificate{*trustedCerts[0], *trustedCerts[1]}
	verifySignerInfo(info, req, t)
}

func TestVerifyErrors(t *testing.T) {
	t.Run("when trustedCerts is absent", func(t *testing.T) {
		env, _ := NewSignatureEnvelopeFromBytes([]byte("{}"), JWS_JSON_MEDIA_TYPE)
		_, err := env.Verify([]x509.Certificate{})
		if !(err != nil && errors.As(err, new(MalformedArgumentError))) {
			t.Errorf("Expected MalformedArgumentError but not found")
		}
	})

	t.Run("when trustedCerts are not trusted", func(t *testing.T) {
		env, _ := NewSignatureEnvelopeFromBytes([]byte(TEST_VALID_SIG), JWS_JSON_MEDIA_TYPE)
		if _, err := env.Verify([]x509.Certificate{*testhelper.GetRoot2Certificate().Cert}); err != nil {
			if !errors.As(err, &UntrustedSignatureError{}) {
				t.Errorf("Expected %T but found %T", &UntrustedSignatureError{}, err)
			}
		} else {
			t.Errorf("Expected UntrustedSignatureError but not found")
		}
	})

	t.Run("when invalid signature is provided", func(t *testing.T) {
		env, _ := NewSignatureEnvelopeFromBytes([]byte(TEST_INVALID_SIG), JWS_JSON_MEDIA_TYPE)
		if _, err := env.Verify([]x509.Certificate{*testhelper.GetRoot2Certificate().Cert}); err != nil {
			if !errors.As(err, &InvalidSignatureError{}) {
				t.Errorf("Expected %T but found %T", InvalidSignatureError{}, err)
			}
		} else {
			t.Errorf("Expected MalformedArgumentError but not found")
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	// Sign
	env, err := NewSignatureEnvelope(JWS_JSON_MEDIA_TYPE)
	if err != nil {
		t.Fatalf("NewSignatureEnvelope() error = %v", err)
	}

	req := getSignRequest()
	sig, err := env.Sign(req)
	if err != nil || len(sig) == 0 {
		t.Fatalf("Sign() error = %v", err)
	}

	//Verify using same env struct
	cert, err := env.Verify([]x509.Certificate{*testhelper.GetRootCertificate().Cert})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !cert.Equal(testhelper.GetRootCertificate().Cert) {
		t.Fatalf("Expected cert with subject %s but found cert with subject %s", cert.Subject, testhelper.GetRootCertificate().Cert.Subject)
	}

	info, err := env.GetSignerInfo()
	if err != nil {
		t.Fatalf("GetSignerInfo() error = %v", err)
	}

	verifySignerInfo(info, req, t)
}

func TestGetSignerInfoErrors(t *testing.T) {
	env, _ := NewSignatureEnvelope(JWS_JSON_MEDIA_TYPE)
	t.Run("when called GetSignerInfo before sign or verify.", func(t *testing.T) {
		_, err := env.GetSignerInfo()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but not found")
		}
	})

	t.Run("when called GetSignerInfo after failed sign or verify call.", func(t *testing.T) {
		req := getSignRequest()
		req.Payload = []byte("Sad")
		env.Sign(req)
		env.Verify([]x509.Certificate{*testhelper.GetRoot2Certificate().Cert})
		_, err := env.GetSignerInfo()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but not found")
		}
	})
}

type MySigner struct {
	rsaKey rsa.PrivateKey
}

func (m MySigner) Sign(bytes []byte) ([]byte, error) {
	hasher := crypto.SHA512.New()
	hasher.Write(bytes)
	// Sign the string and return the encoded bytes
	return rsa.SignPSS(rand.Reader, &m.rsaKey, crypto.SHA512, hasher.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func getSignRequest() SignRequest {
	return SignRequest{
		Payload:            []byte(TEST_PAYLOAD),
		PayloadContentType: JWS_PAYLOAD_CONTENT_TYPE,
		CertificateChain:   []x509.Certificate{*testhelper.GetLeafCertificate().Cert, *testhelper.GetRootCertificate().Cert},
		SigningTime:        time.Now(),
		Expiry:             time.Now().AddDate(0, 0, 1),
		ExtendedSignedAttrs: []Attributes{
			{Key: "signedCritKey1", Value: "signedValue1", Critical: true},
			{Key: "signedKey1", Value: "signedKey2", Critical: false}},
		SigningAgent:      "NotationUnitTest/1.0.0",
		SignatureProvider: MySigner{rsaKey: *testhelper.GetLeafCertificate().PrivateKey},
	}
}

func verifySignerInfo(signInfo SignerInfo, request SignRequest, t *testing.T) {
	if request.SigningAgent != signInfo.UnsignedAttributes.SigningAgent {
		t.Errorf("SigningAgent: expected value %q but found %q", request.SigningAgent, signInfo.UnsignedAttributes.SigningAgent)
	}

	if !reflect.DeepEqual(request.CertificateChain, signInfo.CertificateChain) {
		t.Errorf("Mistmatch between expected and actual CertificateChain")
	}

	if request.SigningTime.Format(time.RFC3339) != signInfo.SignedAttributes.SigningTime.Format(time.RFC3339) {
		t.Errorf("SigningTime: expected value %q but found %q", request.SigningTime, signInfo.SignedAttributes.SigningTime)
	}

	if request.Expiry.Format(time.RFC3339) != signInfo.SignedAttributes.Expiry.Format(time.RFC3339) {
		t.Errorf("Expiry: expected value %q but found %q", request.SigningTime, signInfo.SignedAttributes.Expiry)
	}

	if !reflect.DeepEqual(request.ExtendedSignedAttrs, signInfo.SignedAttributes.ExtendedAttributes) {
		if !(len(request.ExtendedSignedAttrs) == 0 && len(signInfo.SignedAttributes.ExtendedAttributes) == 0) {
			t.Errorf("Mistmatch between expected and actual ExtendedAttributes")
		}
	}

	if request.PayloadContentType != signInfo.PayloadContentType {
		t.Errorf("PayloadContentType: expected value %q but found %q", request.PayloadContentType, signInfo.PayloadContentType)
	}

	// The input payload and the payload signed are different because the jwt library we are using converts
	// payload to map and then to json but the content of payload should be same
	var requestPay map[string]interface{}
	if err := json.Unmarshal(request.Payload, &requestPay); err != nil {
		t.Log(err)
	}

	var signerInfoPay map[string]interface{}
	if err := json.Unmarshal(signInfo.Payload, &signerInfoPay); err != nil {
		t.Log(err)
	}

	if !reflect.DeepEqual(signerInfoPay, signerInfoPay) {
		t.Errorf("Payload: expected value %q but found %q", requestPay, signerInfoPay)
	}
}

func verifySignWithRequest(env SignatureEnvelope, req SignRequest, t *testing.T) {
	sig, err := env.Sign(req)
	if err != nil || len(sig) == 0 {
		t.Fatalf("Sign() error = %v", err)
	}

	info, err := env.GetSignerInfo()
	if err != nil {
		t.Fatalf("GetSignerInfo() error = %v", err)
	}

	verifySignerInfo(info, req, t)
}


func verifySignErrorWithRequest(env SignatureEnvelope, req SignRequest, t *testing.T) {
	_, err := env.Sign(req);
	if !(err != nil && errors.As(err, new(MalformedSignRequestError))) {
		t.Errorf("Expected MalformedArgumentError but not found")
	}
}

