package signer

import "fmt"

// InvalidSignatureError is used when the Signature associated is no longer valid.
type InvalidSignatureError struct{
	err error
}

func (e InvalidSignatureError) Error() string {
	return fmt.Sprintf("The Signature is invalid. Error: %s", e.err.Error())
}

// MalformedSignatureError is used when Signature envelope is malformed.
type MalformedSignatureError struct {
	msg string
}

func (e MalformedSignatureError) Error() string {
	if len(e.msg) != 0 {
		return e.msg
	} else {
		return "The Signature envelope format is malformed"
	}
}

// UnsupportedSignatureFormatError is used when Signature envelope is not supported.
type UnsupportedSignatureFormatError struct {
	mediaType string
}

func (e UnsupportedSignatureFormatError) Error() string {
	return fmt.Sprintf("The Signature envelope format with media type '%s' is not supported", e.mediaType)
}

// SignatureNotFoundError is used when signature envelope is not signed.
type SignatureNotFoundError struct{}

func (e SignatureNotFoundError) Error() string {
	return "Signature envelope not present."
}

// UntrustedSignatureError is used when signature is not generated using trusted certificates.
type UntrustedSignatureError struct{}

func (e UntrustedSignatureError) Error() string {
	return "Signature not generated using specified trusted certificates"
}

// UnsupportedOperationError is used when an operation is not supported.
type UnsupportedOperationError struct{
	operation string
}

func (e UnsupportedOperationError) Error() string {
	return fmt.Sprintf("%s operation is not supported", e.operation)
}

// UnSupportedSigningKeyError is used when a signing key is not supported
type UnSupportedSigningKeyError struct{
	keyType string
}

func (e UnSupportedSigningKeyError) Error() string {
	if len(e.keyType) != 0 {
		return fmt.Sprintf("%s signing key is not supported", e.keyType)
	} else {
		return "The signing key is not supported"
	}
}

// MalformedArgumentError is used when an argument to a function is malformed.
type MalformedArgumentError struct{
	param string
	err error
}

func (e MalformedArgumentError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%q param is malformed. Error: %s", e.param, e.err.Error())
	} else {
		return fmt.Sprintf("%q param is malformed", e.param)
	}
}

// MalformedSignRequestError is used when SignRequest is malformed.
type MalformedSignRequestError struct {
	msg string
}

func (e MalformedSignRequestError) Error() string {
	if len(e.msg) != 0 {
		return e.msg
	} else {
		return "The SignRequest is malformed"
	}
}

// SignatureAlgoNotSupportedError is used when signing algo is not supported.
type SignatureAlgoNotSupportedError struct{
	alg string
}

func (e SignatureAlgoNotSupportedError) Error() string {
	return fmt.Sprintf("%s algorithm is not supported", e.alg)
}