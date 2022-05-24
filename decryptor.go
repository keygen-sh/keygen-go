package keygen

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

type decryptor struct {
	Secret string
}

func (d *decryptor) DecryptCertificate(cert *certificate) ([]byte, error) {
	parts := strings.SplitN(cert.Enc, ".", 3)

	// Decode parts
	ciphertext, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	iv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	tag, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	// Hash secret
	h := sha256.New()
	h.Write([]byte(d.Secret))

	key := h.Sum(nil)

	// Setup AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aes, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Append auth tag to ciphertext
	ciphertext = append(ciphertext, tag...)

	// Decrypt
	plaintext, err := aes.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, ErrLicenseFileInvalid
	}

	return plaintext, nil
}
