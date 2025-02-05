package keygen

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

// MachineFile represents a Keygen license file.
type MachineFile struct {
	ID          string    `json:"-"`
	Type        string    `json:"-"`
	Certificate string    `json:"certificate"`
	Issued      time.Time `json:"issued"`
	Expiry      time.Time `json:"expiry"`
	TTL         int       `json:"ttl"`
	MachineID   string    `json:"-"`
	LicenseID   string    `json:"-"`
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (lic *MachineFile) SetID(id string) error {
	lic.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (lic *MachineFile) SetType(t string) error {
	lic.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (lic *MachineFile) SetData(to func(target interface{}) error) error {
	return to(lic)
}

// SetRelationships implements the jsonapi.UnmarshalRelationship interface.
func (lic *MachineFile) SetRelationships(relationships map[string]interface{}) error {
	if relationship, ok := relationships["machine"]; ok {
		lic.MachineID = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	if relationship, ok := relationships["license"]; ok {
		lic.LicenseID = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	return nil
}

// Decrypt verifies the machine file's signature. It returns any errors
// that occurred during verification, e.g. ErrMachineFileInvalid.
func (lic *MachineFile) Verify() error {
	verifier := &verifier{PublicKey: PublicKey}

	if err := verifier.VerifyMachineFile(lic); err != nil {
		return &MachineFileError{err}
	}

	return nil
}

// Decrypt decrypts the machine file's encrypted dataset. It returns the decrypted dataset
// and any errors that occurred during decryption, e.g. ErrMachineFileNotEncrypted.
func (lic *MachineFile) Decrypt(key string) (*MachineFileDataset, error) {
	cert, err := lic.certificate()
	if err != nil {
		return nil, err
	}

	switch {
	case cert.Alg == "aes-256-gcm+rsa-pss-sha256" || cert.Alg == "aes-256-gcm+rsa-sha256":
		return nil, ErrMachineFileNotSupported
	case cert.Alg != "aes-256-gcm+ed25519":
		return nil, ErrMachineFileNotEncrypted
	}

	// Decrypt
	decryptor := &decryptor{key}
	data, err := decryptor.DecryptCertificate(cert)
	if err != nil {
		return nil, &MachineFileError{err}
	}

	// Unmarshal
	dataset := &MachineFileDataset{}

	if _, err := jsonapi.Unmarshal(data, dataset); err != nil {
		return nil, &MachineFileError{err}
	}

	if MaxClockDrift >= 0 && time.Until(dataset.Issued) > MaxClockDrift {
		return dataset, ErrSystemClockUnsynced
	}

	if dataset.TTL != 0 && time.Now().After(dataset.Expiry) {
		return dataset, ErrMachineFileExpired
	}

	return dataset, nil
}

func (lic *MachineFile) certificate() (*certificate, error) {
	payload := strings.TrimSpace(lic.Certificate)

	// Remove header and footer
	payload = strings.TrimPrefix(payload, "-----BEGIN MACHINE FILE-----")
	payload = strings.TrimSuffix(payload, "-----END MACHINE FILE-----")
	payload = strings.TrimSpace(payload)

	// Decode
	dec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, &MachineFileError{err}
	}

	// Unmarshal
	var cert *certificate
	if err := json.Unmarshal(dec, &cert); err != nil {
		return nil, &MachineFileError{err}
	}

	return cert, nil
}

// MachineFileDataset represents a decrypted machine file object.
type MachineFileDataset struct {
	Machine      Machine      `json:"-"`
	License      License      `json:"-"`
	Entitlements Entitlements `json:"-"`
	Components   Components   `json:"-"`
	Issued       time.Time    `json:"issued"`
	Expiry       time.Time    `json:"expiry"`
	TTL          int          `json:"ttl"`
}

// SetData implements the jsonapi.UnmarshalData interface.
func (lic *MachineFileDataset) SetData(to func(target interface{}) error) error {
	return to(&lic.Machine)
}

// SetMeta implements jsonapi.UnmarshalMeta interface.
func (lic *MachineFileDataset) SetMeta(to func(target interface{}) error) error {
	return to(&lic)
}

// SetIncluded implements jsonapi.UnmarshalIncluded interface.
func (lic *MachineFileDataset) SetIncluded(relationships []*jsonapi.ResourceObject, unmarshal func(res *jsonapi.ResourceObject, target interface{}) error) error {
	for _, relationship := range relationships {
		switch relationship.Type {
		case "components":
			component := &Component{}
			if err := unmarshal(relationship, component); err != nil {
				return err
			}

			lic.Components = append(lic.Components, *component)
		case "entitlements":
			entitlement := &Entitlement{}
			if err := unmarshal(relationship, entitlement); err != nil {
				return err
			}

			lic.Entitlements = append(lic.Entitlements, *entitlement)
		case "licenses":
			license := &License{}
			if err := unmarshal(relationship, license); err != nil {
				return err
			}

			lic.License = *license
		}
	}

	return nil
}
