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

var (
	ErrResponseSignatureMissing = errors.New("response signature is missing")
	ErrResponseSignatureInvalid = errors.New("response signature is invalid")
	ErrResponseDigestMissing    = errors.New("response digest is missing")
	ErrResponseDigestInvalid    = errors.New("response digest is invalid")
	ErrResponseDateInvalid      = errors.New("response date is invalid")
	ErrResponseDateTooOld       = errors.New("response date is too old")
	ErrPublicKeyMissing         = errors.New("public key is missing")
	ErrPublicKeyInvalid         = errors.New("public key is invalid")
)

type verifier struct {
	PublicKey string
}

// VerifyLicenseFile checks if a license file is genuine.
func (v *verifier) VerifyLicenseFile(lic *LicenseFile) error {
	cert, err := lic.certificate()
	if err != nil {
		return err
	}

	switch {
	case cert.Alg == "aes-256-gcm+ed25519" || cert.Alg == "base64+ed25519":
		if v.PublicKey == "" {
			return ErrPublicKeyMissing
		}

		pubKey, err := hex.DecodeString(v.PublicKey)
		if err != nil {
			return ErrPublicKeyInvalid
		}

		if l := len(pubKey); l != ed25519.PublicKeySize {
			return ErrPublicKeyInvalid
		}

		msg := []byte("license/" + cert.Enc)
		sig, err := base64.StdEncoding.DecodeString(cert.Sig)
		if err != nil {
			return ErrLicenseFileNotGenuine
		}

		if ok := ed25519.Verify(pubKey, msg, sig); !ok {
			return ErrLicenseFileNotGenuine
		}

		return nil
	default:
		return ErrLicenseFileNotSupported
	}
}

// VerifyMachineFile checks if a license file is genuine.
func (v *verifier) VerifyMachineFile(lic *MachineFile) error {
	cert, err := lic.certificate()
	if err != nil {
		return err
	}

	switch {
	case cert.Alg == "aes-256-gcm+ed25519" || cert.Alg == "base64+ed25519":
		if v.PublicKey == "" {
			return ErrPublicKeyMissing
		}

		pubKey, err := hex.DecodeString(v.PublicKey)
		if err != nil {
			return ErrPublicKeyInvalid
		}

		if l := len(pubKey); l != ed25519.PublicKeySize {
			return ErrPublicKeyInvalid
		}

		msg := []byte("machine/" + cert.Enc)
		sig, err := base64.StdEncoding.DecodeString(cert.Sig)
		if err != nil {
			return ErrLicenseFileNotGenuine
		}

		if ok := ed25519.Verify(pubKey, msg, sig); !ok {
			return ErrLicenseFileNotGenuine
		}

		return nil
	default:
		return ErrLicenseFileNotSupported
	}
}

// Verify checks if a license key is genuine by cryptographically verifying the
// key using your PublicKey. If the key is genuine, the decoded dataset from the
// key will be returned. An error will be returned if the key is not genuine or
// otherwise invalid, e.g. ErrLicenseNotGenuine.
func (v *verifier) VerifyLicense(license *License) ([]byte, error) {
	if license.Key == "" {
		return nil, ErrLicenseKeyMissing
	}

	if license.Scheme == "" {
		return nil, ErrLicenseSchemeMissing
	}

	switch {
	case license.Scheme == SchemeCodeEd25519:
		dataset, err := v.verifyKey(license.Key)

		return dataset, err
	default:
		return nil, ErrLicenseSchemeNotSupported
	}
}

func (v *verifier) verifyKey(key string) ([]byte, error) {
	if v.PublicKey == "" {
		return nil, ErrPublicKeyMissing
	}

	pubKey, err := hex.DecodeString(v.PublicKey)
	if err != nil {
		return nil, ErrPublicKeyInvalid
	}

	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, ErrPublicKeyInvalid
	}

	parts := strings.SplitN(key, ".", 2)
	signingData := parts[0]
	encSig := parts[1]

	parts = strings.SplitN(signingData, "/", 2)
	signingPrefix := parts[0]
	encDataset := parts[1]

	if signingPrefix != "key" {
		return nil, ErrLicenseKeyNotGenuine
	}

	msg := []byte("key/" + encDataset)
	sig, err := base64.URLEncoding.DecodeString(encSig)
	if err != nil {
		return nil, ErrLicenseKeyNotGenuine
	}

	dataset, err := base64.URLEncoding.DecodeString(encDataset)
	if err != nil {
		return nil, ErrLicenseKeyNotGenuine
	}

	if ok := ed25519.Verify(pubKey, msg, sig); !ok {
		return nil, ErrLicenseKeyNotGenuine
	}

	return dataset, nil
}

func verifyResponseSignature(publicKey string, response *Response) error {
	if publicKey == "" {
		return ErrPublicKeyMissing
	}

	pubKey, err := hex.DecodeString(publicKey)
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
