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

func Genuine(signedKey string, scheme string) error {
	if PublicKey == "" {
		return ErrPublicKeyMissing
	}

	switch {
	case scheme == SchemeCodeEd25519:
		return verifyEd25519SignedKey(signedKey)
	default:
		return ErrLicenseSchemeNotSupported
	}
}

func verifyEd25519SignedKey(signedKey string) error {
	pubKey, err := hex.DecodeString(PublicKey)
	if err != nil {
		return ErrPublicKeyInvalid
	}

	if l := len(pubKey); l != ed25519.PublicKeySize {
		return ErrPublicKeyInvalid
	}

	parts := strings.SplitN(signedKey, ".", 2)
	signingData := parts[0]
	encSig := parts[1]

	parts = strings.SplitN(signingData, "/", 2)
	signingPrefix := parts[0]
	encData := parts[1]

	if signingPrefix != "key" {
		return ErrLicenseNotGenuine
	}

	data := []byte("key/" + encData)
	sig, err := base64.URLEncoding.DecodeString(encSig)
	if err != nil {
		return ErrLicenseNotGenuine
	}

	if ok := ed25519.Verify(pubKey, data, sig); !ok {
		return ErrLicenseNotGenuine
	}

	return nil
}
