package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/notaryproject/notation-core-go/signer"
	"math/big"
	"time"
)

func main() {
	verify()
}

func verify() {

	if _, err := base64.RawURLEncoding.DecodeString(""); err != nil {
		fmt.Println(err)
	}

	//sig := "{\r\n  \"payload\": \"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\",\r\n  \"protected\":\"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImNyaXQiOlsidHlwIiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiLCJtYXJrZWRDcml0Il0sImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIjoiMjAwNi0wMS0wMlQxNTowNDowNVoiLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiOiIyMDA2LTAxLTAyVDE1OjA0OjA1WiIsIm1hcmtlZENyaXQiOiJIb2xhIiwibm90TWFya2VkQ3JpdCI6IkhvbGEiLCJudW0iOjEyM30\",\r\n  \"header\": {\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\r\n  \"signature\":\"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q\"\r\n}"
	sig, cert:=sign()
	fmt.Println(string(sig))
	sigEnv, _ := signer.NewSignatureEnvelopeFromBytes(sig, signer.JWS_JSON_MEDIA_TYPE)
	fmt.Println("============================================================")
	_, err := sigEnv.Verify([]x509.Certificate{cert})
	fmt.Println(err)
	fmt.Println("============================================================")
	info,_ := sigEnv.GetSignerInfo()
	fmt.Println(info.SignedAttributes)

	fmt.Println("============================================================")
	//fmt.Println(sigEnv.GetSignerInfo())
	// sigInfo, err := sigEnv.GetSignerInfo()
	// fmt.Println(sigInfo.SignedAttributes.ExtendedAttributes, err)

}

func sign() ([]byte, x509.Certificate) {
	// ok, lets populate the certificate with some data
	// not all fields in Certificate will be populated
	// see Certificate structure at
	// http://golang.org/pkg/crypto/x509/#Certificate
	template := &x509.Certificate {
		IsCA : true,
		BasicConstraintsValid : true,
		SubjectKeyId : []byte{1,2,3},
		SerialNumber : big.NewInt(1234),
		Subject : pkix.Name{
			Country : []string{"Earth"},
			Organization: []string{"Mamma Nature"},
		},
		NotBefore : time.Now(),
		NotAfter : time.Now().AddDate(5,5,5),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage : []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage : x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
	}

	// generate private key
	privatekey, err := rsa.GenerateKey(rand.Reader, 3072)

	if err != nil {
		fmt.Println(err)
	}

	publickey := &privatekey.PublicKey
	pubASN1,_:= x509.MarshalPKIXPublicKey(publickey)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	fmt.Println(string(pubBytes))
	// create a self-signed certificate. template = parent
	var parent = template
	cert, _ := x509.CreateCertificate(rand.Reader, template, parent, publickey,privatekey)
	certing ,_ := x509.ParseCertificate(cert)

	req := signer.SignRequest{
		Payload: []byte("{\n  \"iss\": \"DinoChiesa.github.io\",\n  \"sub\": \"olaf\",\n  \"aud\": \"audrey\",\n  \"iat\": 1654586282,\n  \"exp\": 1654586882\n}"),
		CertificateChain: []x509.Certificate{*certing},
		Expiry: time.Now().Add(time.Hour * 120),
		SigningTime: time.Now(),
		SigningAgent: "Hey! I came from pritesb@",
		PayloadContentType: signer.JWS_PAYLOAD_CONTENT_TYPE,
		ExtendedSignedAttrs: []signer.Attributes{
			{Key: "MyKey1", Value: "MyValue1", Critical: true},
			{Key: "MyKey2", Value: "MyValue2", Critical: false},
			{Key: "MyKey3", Value: "MyValue3", Critical: true},
		},
		SignatureProvider: MySigner{
			rsaKey: *privatekey,
		},
	}

	signer, err := signer.NewSignatureEnvelope(signer.JWS_JSON_MEDIA_TYPE)
	fmt.Println(err)
	sig, err := signer.Sign(req)
	fmt.Println(err)
	return sig, *certing
}

type MySigner struct {
	rsaKey rsa.PrivateKey
}

func (m MySigner) Sign(bytes []byte) ([]byte, error) {

	hasher := crypto.SHA384.New()
	hasher.Write(bytes)

	// Sign the string and return the encoded bytes
	return rsa.SignPSS(rand.Reader, &m.rsaKey,  crypto.SHA384, hasher.Sum(nil),  &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}