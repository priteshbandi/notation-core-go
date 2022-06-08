package main

import (
	"crypto/x509"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signer"
)

func main() {
	sig := "{\r\n  \"payload\": \"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\",\r\n  \"protected\":\"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImNyaXQiOlsidHlwIiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiLCJtYXJrZWRDcml0Il0sImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIjoiMjAwNi0wMS0wMlQxNTowNDowNVoiLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiOiIyMDA2LTAxLTAyVDE1OjA0OjA1WiIsIm1hcmtlZENyaXQiOiJIb2xhIiwibm90TWFya2VkQ3JpdCI6IkhvbGEiLCJudW0iOjEyM30\",\r\n  \"header\": {\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\r\n  \"signature\":\"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q\"\r\n}"
	sigEnv, _ := signer.NewSignatureEnvelopeFromBytes([]byte(sig), signer.JWS_JSON_MEDIA_TYPE)
	sigEnv.Verify([]x509.Certificate{})
	sigInfo, err := sigEnv.GetSignerInfo()
	fmt.Println(sigInfo.SignedAttributes.ExtendedAttributes, err)
	// jwtTest()
}

func jwtTest() {
	tokenString := "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImNyaXQiOlsidHlwIiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiLCJtYXJrZWRDcml0Il0sImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIjoiMjAwNi0wMS0wMlQxNTowNDowNVoiLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiOiIyMDA2LTAxLTAyVDE1OjA0OjA1WiIsIm1hcmtlZENyaXQiOiJIb2xhIiwibm90TWFya2VkQ3JpdCI6IkhvbGEiLCJudW0iOjEyM30.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6Im9sYWYiLCJhdWQiOiJhdWRyZXkiLCJpYXQiOjE2NTQ1ODYyODIsImV4cCI6MTY1NDU4Njg4Mn0.G9AKTa7LI0AJ3Nkavv6PIDN8qSebkQwaghFAbs78JhYlm51tyKs4boOZQ1XJ8QnKxD3MI2n-M8p_Yb7nkVJoPDHKivvFuCteOfMYYEoWWGscm66Unl5FZlFUQQEUdIklouVoSCTgyJC-gV8kIQHf8PjPbpB1o_lGwSf3R-OhoYEvNV9kmN21wrtNCHGOxSgSyRLiQgRGUC1jniimyXfeBHgNgstXgDLYylJlGjhyf0ch3obThPEQQuTnqvT_RecYOXCVBsa2z7g0OB4tttbRHKbANX_ecYRgDhhcoBhkmgwWlLO-Lxka3xtITnI8-NvBiEs-rJf549Q6wK4vIh2d1w"
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})
	fmt.Printf(token.Method.Alg())
	fmt.Printf(token.Signature)
}
