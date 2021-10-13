package keygen

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	SchemeCodeEd25519 = "ED25519_SIGN"
)

var (
	ErrLicenseSchemeNotSupported = errors.New("license scheme is not supported")
	ErrLicenseSchemeMissing      = errors.New("license scheme is missing")
	ErrLicenseKeyMissing         = errors.New("license key is missing")
	ErrLicenseNotGenuine         = errors.New("license key is not genuine")
	ErrPublicKeyMissing          = errors.New("public key is missing")
	ErrPublicKeyInvalid          = errors.New("public key is invalid")
)

// Genuine checks if a license key is genuine by cryptographically verifying the
// key using your PublicKey. If the key is genuine, the decoded dataset from the
// key will be returned. An error will be returned if the key is not genuine or
// otherwise invalid, e.g. ErrLicenseNotGenuine.
func Genuine(licenseKey string, signingScheme string) ([]byte, error) {
	if PublicKey == "" {
		return nil, ErrPublicKeyMissing
	}

	if licenseKey == "" {
		return nil, ErrLicenseKeyMissing
	}

	if signingScheme == "" {
		return nil, ErrLicenseSchemeMissing
	}

	switch {
	case signingScheme == SchemeCodeEd25519:
		dataset, err := verifyEd25519SignedKey(licenseKey)

		return dataset, err
	default:
		return nil, ErrLicenseSchemeNotSupported
	}
}

func verifyEd25519SignedKey(signedKey string) ([]byte, error) {
	pubKey, err := hex.DecodeString(PublicKey)
	if err != nil {
		return nil, ErrPublicKeyInvalid
	}

	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, ErrPublicKeyInvalid
	}

	parts := strings.SplitN(signedKey, ".", 2)
	signingData := parts[0]
	encSig := parts[1]

	parts = strings.SplitN(signingData, "/", 2)
	signingPrefix := parts[0]
	encDataset := parts[1]

	if signingPrefix != "key" {
		return nil, ErrLicenseNotGenuine
	}

	message := []byte("key/" + encDataset)
	sig, err := base64.URLEncoding.DecodeString(encSig)
	if err != nil {
		return nil, ErrLicenseNotGenuine
	}

	dataset, err := base64.URLEncoding.DecodeString(encDataset)
	if err != nil {
		return nil, ErrLicenseNotGenuine
	}

	if ok := ed25519.Verify(pubKey, message, sig); !ok {
		return nil, ErrLicenseNotGenuine
	}

	return dataset, nil
}
