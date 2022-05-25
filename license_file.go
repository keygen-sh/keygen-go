package keygen

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

var (
	ErrLicenseFileNotSupported  = errors.New("license file is not supported")
	ErrLicenseFileNotEncrypted  = errors.New("license file is not encrypted")
	ErrLicenseFileNotGenuine    = errors.New("license file is not genuine")
	ErrLicenseFileInvalid       = errors.New("license file is not valid")
	ErrLicenseFileSecretMissing = errors.New("license file secret is missing")
)

// LicenseFile represents a Keygen license file.
type LicenseFile struct {
	ID          string `json:"-"`
	Type        string `json:"-"`
	Certificate string `json:"certificate"`
	LicenseID   string `json:"-"`
}

// Implement jsonapi.UnmarshalData interface
func (lic *LicenseFile) SetID(id string) error {
	lic.ID = id
	return nil
}

func (lic *LicenseFile) SetType(t string) error {
	lic.Type = t
	return nil
}

func (lic *LicenseFile) SetData(to func(target interface{}) error) error {
	return to(lic)
}

func (lic *LicenseFile) SetRelationships(relationships map[string]interface{}) error {
	if relationship, ok := relationships["license"]; ok {
		lic.LicenseID = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	return nil
}

func (lic *LicenseFile) Verify() error {
	verifier := &verifier{PublicKey: PublicKey}

	if err := verifier.VerifyLicenseFile(lic); err != nil {
		return ErrLicenseFileInvalid
	}

	return nil
}

func (lic *LicenseFile) Decrypt(key string) (*LicenseFileDataset, error) {
	cert, err := lic.certificate()
	if err != nil {
		return nil, err
	}

	switch {
	case cert.Alg == "aes-256-gcm+rsa-pss-sha256" || cert.Alg == "aes-256-gcm+rsa-sha256":
		return nil, ErrLicenseFileNotSupported
	case cert.Alg != "aes-256-gcm+ed25519":
		return nil, ErrLicenseFileNotEncrypted
	}

	// Decrypt
	decryptor := &decryptor{key}
	data, err := decryptor.DecryptCertificate(cert)
	if err != nil {
		return nil, err
	}

	// Unmarshal
	dataset := &LicenseFileDataset{}

	if _, err := jsonapi.Unmarshal(data, dataset); err != nil {
		return nil, err
	}

	return dataset, nil
}

func (lic *LicenseFile) certificate() (*certificate, error) {
	payload := lic.Certificate

	// Remove header and footer
	payload = strings.TrimPrefix(payload, "-----BEGIN LICENSE FILE-----\n")
	payload = strings.TrimSuffix(payload, "-----END LICENSE FILE-----\n")

	// Decode
	dec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}

	// Unmarshal
	var cert *certificate
	if err := json.Unmarshal(dec, &cert); err != nil {
		return nil, err
	}

	return cert, nil
}

type LicenseFileDataset struct {
	License      License      `json:"-"`
	Entitlements Entitlements `json:"-"`
	Issued       time.Time    `json:"issued"`
	Expiry       time.Time    `json:"expiry"`
	TTL          int          `json:"ttl"`
}

func (lic *LicenseFileDataset) SetData(to func(target interface{}) error) error {
	return to(&lic.License)
}

func (lic *LicenseFileDataset) SetMeta(to func(target interface{}) error) error {
	return to(&lic)
}

func (lic *LicenseFileDataset) SetIncluded(relationships []*jsonapi.ResourceObject, unmarshal func(included *jsonapi.ResourceObject, target interface{}) error) error {
	for _, relationship := range relationships {
		switch relationship.Type {
		case "entitlements":
			entitlement := &Entitlement{}
			if err := unmarshal(relationship, entitlement); err != nil {
				return err
			}

			lic.Entitlements = append(lic.Entitlements, *entitlement)
		}
	}

	return nil
}
