package signer

import "fmt"

// InvalidSignatureError is used when the signature assocaited is no longer valid.
type InvalidSignatureError struct{}

func (e *InvalidSignatureError) Error() string {
	return "The signature is invalid."
}

// MalformedSignatureError is used when signature envelope is malformed.
type MalformedSignatureError struct {
	msg string
}

func (e *MalformedSignatureError) Error() string {
	if len(e.msg) != 0 {
		return e.msg
	} else {
		return "The signature envelope format is malformed"
	}
}

// UnsupportedSignatureFormatError is used when signature envelope is not supported.
type UnsupportedSignatureFormatError struct {
	mediaType string
}

func (e *UnsupportedSignatureFormatError) Error() string {
	return fmt.Sprintf("The signature envelope format with media type '%s' is not supported.", e.mediaType)
}

// SignatureNotFoundError is used when envelope is unsigned.
type SignatureNotFoundError struct{}

func (e *SignatureNotFoundError) Error() string {
	return ("Signature not present. Please sign before verify.")
}

// SignatureNotTrustedError is used when envelope is unsigned.
type SignatureNotTrustedError struct{}

func (e *SignatureNotTrustedError) Error() string {
	return ("Signature not present. Please sign before verify.")
}

// SignatureNotTrustedError is used when envelope is unsigned.
type UnsupportedOperationError struct{}

func (e *UnsupportedOperationError) Error() string {
	return ("Signature not present. Please sign before verify.")
}
