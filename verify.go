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
	ErrLicenseNotGenuine         = errors.New("license is not genuine")
	ErrPublicKeyMissing          = errors.New("public key is missing")
	ErrPublicKeyInvalid          = errors.New("public key is invalid")
)

func Genuine(signedKey string, signingScheme string) ([]byte, error) {
	if PublicKey == "" {
		return nil, ErrPublicKeyMissing
	}

	switch {
	case signingScheme == SchemeCodeEd25519:
		dataset, err := verifyEd25519SignedKey(signedKey)

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
