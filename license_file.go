package keygen

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

// LicenseFile represents a Keygen license file.
type LicenseFile struct {
	ID          string    `json:"-"`
	Type        string    `json:"-"`
	Certificate string    `json:"certificate"`
	Issued      time.Time `json:"issued"`
	Expiry      time.Time `json:"expiry"`
	TTL         int       `json:"ttl"`
	LicenseID   string    `json:"-"`
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (lic *LicenseFile) SetID(id string) error {
	lic.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (lic *LicenseFile) SetType(t string) error {
	lic.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (lic *LicenseFile) SetData(to func(target interface{}) error) error {
	return to(lic)
}

// SetRelationships implements the jsonapi.UnmarshalRelationship interface.
func (lic *LicenseFile) SetRelationships(relationships map[string]interface{}) error {
	if relationship, ok := relationships["license"]; ok {
		lic.LicenseID = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	return nil
}

// Decrypt verifies the license file's signature. It returns any errors
// that occurred during verification, e.g. ErrLicenseFileInvalid.
func (lic *LicenseFile) Verify() error {
	verifier := &verifier{PublicKey: PublicKey}

	if err := verifier.VerifyLicenseFile(lic); err != nil {
		return &InvalidLicenseFileError{err}
	}

	return nil
}

// Decrypt decrypts the license file's encrypted dataset. It returns the decrypted dataset
// and any errors that occurred during decryption, e.g. ErrLicenseFileNotEncrypted.
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
		return nil, &InvalidLicenseFileError{err}
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
		return nil, &InvalidLicenseFileError{err}
	}

	// Unmarshal
	var cert *certificate
	if err := json.Unmarshal(dec, &cert); err != nil {
		return nil, &InvalidLicenseFileError{err}
	}

	return cert, nil
}

// LicenseFileDataset represents a decrypted license file object.
type LicenseFileDataset struct {
	License      License      `json:"-"`
	Entitlements Entitlements `json:"-"`
	Issued       time.Time    `json:"issued"`
	Expiry       time.Time    `json:"expiry"`
	TTL          int          `json:"ttl"`
}

// SetData implements the jsonapi.UnmarshalData interface.
func (lic *LicenseFileDataset) SetData(to func(target interface{}) error) error {
	return to(&lic.License)
}

// SetMeta implements jsonapi.UnmarshalMeta interface.
func (lic *LicenseFileDataset) SetMeta(to func(target interface{}) error) error {
	return to(&lic)
}

// SetIncluded implements jsonapi.UnmarshalIncluded interface.
func (lic *LicenseFileDataset) SetIncluded(relationships []*jsonapi.ResourceObject, unmarshal func(res *jsonapi.ResourceObject, target interface{}) error) error {
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
