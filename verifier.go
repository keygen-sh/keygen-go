package keygen

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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

	msg := []byte("license/" + cert.Enc)
	sig, err := base64.StdEncoding.DecodeString(cert.Sig)
	if err != nil {
		return ErrLicenseFileNotGenuine
	}

	switch cert.Alg {
	case "aes-256-gcm+ed25519", "base64+ed25519":
		publicKey, err := v.publicKeyBytes()
		if err != nil {
			return err
		}

		if ok := ed25519.Verify(publicKey, msg, sig); !ok {
			return ErrLicenseFileNotGenuine
		}
	case "aes-256-gcm+ecdsa-p256", "base64+ecdsa-p256":
		publicKey, err := v.publicKey()
		if err != nil {
			return err
		}

		ecdsaPubKey := publicKey.(*ecdsa.PublicKey)
		hash := sha256.Sum256(msg)

		if !ecdsa.VerifyASN1(ecdsaPubKey, hash[:], sig) {
			return ErrLicenseFileNotGenuine
		}
	default:
		return ErrLicenseFileNotSupported
	}

	return nil
}

// VerifyMachineFile checks if a license file is genuine.
func (v *verifier) VerifyMachineFile(lic *MachineFile) error {
	cert, err := lic.certificate()
	if err != nil {
		return err
	}

	msg := []byte("machine/" + cert.Enc)
	sig, err := base64.StdEncoding.DecodeString(cert.Sig)
	if err != nil {
		return ErrMachineFileNotGenuine
	}

	switch cert.Alg {
	case "aes-256-gcm+ed25519", "base64+ed25519":
		publicKey, err := v.publicKeyBytes()
		if err != nil {
			return err
		}

		if ok := ed25519.Verify(publicKey, msg, sig); !ok {
			return ErrMachineFileNotGenuine
		}
	case "aes-256-gcm+ecdsa-p256", "base64+ecdsa-p256":
		publicKey, err := v.publicKey()
		if err != nil {
			return err
		}

		ecdsaPubKey := publicKey.(*ecdsa.PublicKey)
		hash := sha256.Sum256(msg)

		if !ecdsa.VerifyASN1(ecdsaPubKey, hash[:], sig) {
			return ErrMachineFileNotGenuine
		}
	default:
		return ErrMachineFileNotSupported
	}

	return nil
}

// Verify checks if a license key is genuine by cryptographically verifying the
// key using your PublicKey. If the key is genuine, the decoded dataset from the
// key will be returned. An error will be returned if the key is not genuine or
// otherwise invalid, e.g. ErrLicenseNotGenuine.
func (v *verifier) VerifyLicense(license *License) ([]byte, error) {
	if license.Scheme == "" {
		return nil, ErrLicenseSchemeMissing
	}

	if license.Key == "" {
		return nil, ErrLicenseKeyMissing
	}

	return v.verifyKey(license.Scheme, license.Key)
}

func (v *verifier) VerifyRequest(request *http.Request) error {
	digestHeader := request.Header.Get("Digest")
	if digestHeader == "" {
		return ErrRequestDigestMissing
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		return err
	}

	// We need to close and replace the body so that others can read
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewBuffer(body))

	shasum := sha256.Sum256(body)
	digest := "sha-256=" + base64.StdEncoding.EncodeToString(shasum[:])
	if digest != digestHeader {
		return ErrRequestDigestInvalid
	}

	date := request.Header.Get("Date")
	if date == "" {
		return ErrRequestDateMissing
	}

	t, err := time.Parse(time.RFC1123, date)
	if err != nil {
		return err
	}

	if MaxClockDrift >= 0 && time.Since(t) > MaxClockDrift {
		return ErrRequestDateTooOld
	}

	method := strings.ToLower(request.Method)
	host := request.Host
	url := request.URL
	path := url.EscapedPath()
	if path == "" {
		path = "/"
	}

	if url.RawQuery != "" {
		path += "?" + url.RawQuery
	}

	sigHeader := request.Header.Get("Keygen-Signature")
	if sigHeader == "" {
		return ErrRequestSignatureMissing
	}

	sigParams := parseSignatureHeader(sigHeader)
	alg := sigParams["algorithm"]
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
		return err
	}

	// we only support ed25519 and ecdsa p256 (nist p-256)
	switch alg {
	case "ed25519":
		publicKey, err := v.publicKeyBytes()
		if err != nil {
			return err
		}

		if ok := ed25519.Verify(publicKey, msgBytes, sigBytes); !ok {
			return ErrResponseSignatureInvalid
		}
	case "ecdsa-p256":
		publicKey, err := v.publicKey()
		if err != nil {
			return err
		}

		ecdsaPub := publicKey.(*ecdsa.PublicKey)
		hash := sha256.Sum256(msgBytes)

		if !ecdsa.VerifyASN1(ecdsaPub, hash[:], sigBytes) {
			return ErrResponseSignatureInvalid
		}
	default:
		return ErrResponseSignatureNotSupported
	}

	return nil
}

func (v *verifier) VerifyResponse(response *Response) error {
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
	if date == "" {
		return ErrResponseDateMissing
	}

	t, err := time.Parse(time.RFC1123, date)
	if err != nil {
		return err
	}

	if MaxClockDrift >= 0 && time.Since(t) > MaxClockDrift {
		return ErrResponseDateTooOld
	}

	method := strings.ToLower(response.Request.Method)
	url := response.Request.URL
	host := url.Host
	path := url.EscapedPath()
	if path == "" {
		path = "/"
	}

	if url.RawQuery != "" {
		path += "?" + url.RawQuery
	}

	sigHeader := response.Headers.Get("Keygen-Signature")
	if sigHeader == "" {
		return ErrResponseSignatureMissing
	}

	sigParams := parseSignatureHeader(sigHeader)
	alg := sigParams["algorithm"]
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

	// we only support ed25519 and ecdsa p256 (nist p-256)
	switch alg {
	case "ed25519":
		publicKey, err := v.publicKeyBytes()
		if err != nil {
			return err
		}

		if ok := ed25519.Verify(publicKey, msgBytes, sigBytes); !ok {
			return ErrResponseSignatureInvalid
		}
	case "ecdsa-p256":
		publicKey, err := v.publicKey()
		if err != nil {
			return err
		}

		ecdsaPub := publicKey.(*ecdsa.PublicKey)
		hash := sha256.Sum256(msgBytes)

		if !ecdsa.VerifyASN1(ecdsaPub, hash[:], sigBytes) {
			return ErrResponseSignatureInvalid
		}
	default:
		return ErrResponseSignatureNotSupported
	}

	return nil
}

func (v *verifier) verifyKey(scheme SchemeCode, key string) ([]byte, error) {
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

	switch scheme {
	case SchemeCodeEd25519:
		publicKey, err := v.publicKeyBytes()
		if err != nil {
			return nil, err
		}

		if ok := ed25519.Verify(publicKey, msg, sig); !ok {
			return nil, ErrLicenseKeyNotGenuine
		}
	case SchemeCodeP256:
		publicKey, err := v.publicKey()
		if err != nil {
			return nil, err
		}

		ecdsaPub := publicKey.(*ecdsa.PublicKey)
		hash := sha256.Sum256(msg)

		if !ecdsa.VerifyASN1(ecdsaPub, hash[:], sig) {
			return nil, ErrLicenseKeyNotGenuine
		}
	default:
		return nil, ErrSchemeNotSupported
	}

	return dataset, nil
}

func (v *verifier) publicKeyBytes() ([]byte, error) {
	if v.PublicKey == "" {
		return nil, ErrPublicKeyMissing
	}

	key, err := hex.DecodeString(v.PublicKey)
	if err != nil {
		return nil, ErrPublicKeyInvalid
	}

	if l := len(key); l != ed25519.PublicKeySize {
		return nil, ErrPublicKeyInvalid
	}

	return key, nil
}

func (v *verifier) publicKey() (crypto.PublicKey, error) {
	if v.PublicKey == "" {
		return nil, ErrPublicKeyMissing
	}

	block, _ := pem.Decode([]byte(v.PublicKey))
	if block == nil {
		return nil, ErrPublicKeyInvalid
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrPublicKeyInvalid
	}

	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		return nil, ErrPublicKeyInvalid
	}

	return pub, nil
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
