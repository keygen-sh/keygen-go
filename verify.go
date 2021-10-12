package keygen

import "errors"

const (
	SchemeCodeEd25519 = "ED25519_SIGN"
)

var (
	ErrLicenseSchemeNotSupported = errors.New("license scheme is not supported")
	ErrLicenseNotGenuine         = errors.New("license is not genuine")
	ErrPublicKeyMissing          = errors.New("public key is missing")
)

func Genuine(key string, scheme string) error {
	if PublicKey == "" {
		return ErrPublicKeyMissing
	}

	switch {
	case scheme == SchemeCodeEd25519:
		return nil
	default:
		return ErrLicenseSchemeNotSupported
	}
}
