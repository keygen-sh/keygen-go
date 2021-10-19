package keygen

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type SchemeCode string

const (
	SchemeCodeEd25519 SchemeCode = "ED25519_SIGN"
)

var (
	ErrLicenseSchemeNotSupported = errors.New("license scheme is not supported")
	ErrLicenseSchemeMissing      = errors.New("license scheme is missing")
	ErrLicenseKeyMissing         = errors.New("license key is missing")
	ErrLicenseNotGenuine         = errors.New("license key is not genuine")
	ErrResponseSignatureMissing  = errors.New("response signature is missing")
	ErrResponseSignatureInvalid  = errors.New("response signature is invalid")
	ErrResponseDigestMissing     = errors.New("response digest is missing")
	ErrResponseDigestInvalid     = errors.New("response digest is invalid")
	ErrResponseDateInvalid       = errors.New("response date is invalid")
	ErrResponseDateTooOld        = errors.New("response date is too old")
	ErrPublicKeyMissing          = errors.New("public key is missing")
	ErrPublicKeyInvalid          = errors.New("public key is invalid")
)

// Genuine checks if a license key is genuine by cryptographically verifying the
// key using your PublicKey. If the key is genuine, the decoded dataset from the
// key will be returned. An error will be returned if the key is not genuine or
// otherwise invalid, e.g. ErrLicenseNotGenuine.
func Genuine(licenseKey string, signingScheme SchemeCode) ([]byte, error) {
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
	if PublicKey == "" {
		return nil, ErrPublicKeyMissing
	}

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

	msg := []byte("key/" + encDataset)
	sig, err := base64.URLEncoding.DecodeString(encSig)
	if err != nil {
		return nil, ErrLicenseNotGenuine
	}

	dataset, err := base64.URLEncoding.DecodeString(encDataset)
	if err != nil {
		return nil, ErrLicenseNotGenuine
	}

	if ok := ed25519.Verify(pubKey, msg, sig); !ok {
		return nil, ErrLicenseNotGenuine
	}

	return dataset, nil
}

func verifyResponseSignature(response *Response) error {
	if PublicKey == "" {
		return ErrPublicKeyMissing
	}

	pubKey, err := hex.DecodeString(PublicKey)
	if err != nil {
		return ErrPublicKeyInvalid
	}

	if l := len(pubKey); l != ed25519.PublicKeySize {
		return ErrPublicKeyInvalid
	}

	url, err := url.Parse(response.URL)
	if err != nil {
		return err
	}

	digestHeader := response.Headers.Get("Digest")
	if digestHeader == "" {
		return ErrResponseDigestMissing
	}

	shasum := sha256.Sum256(response.Body)
	digest := "sha-256=" + base64.StdEncoding.EncodeToString(shasum[:])
	if digest != digestHeader {
		return ErrResponseDigestInvalid
	}

	date := response.Headers.Get("Date")
	t, err := time.Parse(time.RFC1123, date)
	if err != nil {
		return ErrResponseDateInvalid
	}

	if time.Since(t) > time.Duration(5)*time.Minute {
		return ErrResponseDateTooOld
	}

	method := strings.ToLower(response.Method)
	host := url.Host
	path := url.Path
	if url.RawQuery != "" {
		path += "?" + url.RawQuery
	}

	sigHeader := response.Headers.Get("Keygen-Signature")
	if sigHeader == "" {
		return ErrResponseSignatureMissing
	}

	sigParams := parseSignatureHeader(sigHeader)
	sig := sigParams["signature"]
	msg := fmt.Sprintf(
		"(request-target): %s %s\nhost: %s\ndate: %s\ndigest: %s",
		method,
		path,
		host,
		date,
		digest,
	)

	msgBytes := []byte(msg)
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return ErrResponseSignatureInvalid
	}

	if ok := ed25519.Verify(pubKey, msgBytes, sigBytes); !ok {
		return ErrResponseSignatureInvalid
	}

	return nil
}

func parseSignatureHeader(header string) map[string]string {
	params := make(map[string]string)

	for _, param := range strings.Split(header, ",") {
		kv := strings.SplitN(param, "=", 2)
		k := strings.TrimLeft(kv[0], " ")
		v := strings.Trim(kv[1], `"`)

		params[k] = v
	}

	return params
}
