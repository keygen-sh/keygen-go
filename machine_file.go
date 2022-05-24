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
	ErrMachineFileNotSupported = errors.New("machine file is not supported")
	ErrMachineFileNotEncrypted = errors.New("machine file is not encrypted")
	ErrMachineFileNotGenuine   = errors.New("machine file is not genuine")
	ErrMachineFileInvalid      = errors.New("machine file is not valid")
)

// LicenseFile represents a Keygen license file.
type MachineFile struct {
	ID          string `json:"-"`
	Type        string `json:"-"`
	Certificate string `json:"certificate"`
	MachineID   string `json:"-"`
	LicenseID   string `json:"-"`
	secret      string `json:"-"`
}

// Implement jsonapi.UnmarshalData interface
func (lic *MachineFile) SetID(id string) error {
	lic.ID = id
	return nil
}

func (lic *MachineFile) SetType(t string) error {
	lic.Type = t
	return nil
}

func (lic *MachineFile) SetData(to func(target interface{}) error) error {
	return to(lic)
}

func (lic *MachineFile) SetRelationships(relationships map[string]interface{}) error {
	if relationship, ok := relationships["machine"]; ok {
		lic.MachineID = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	if relationship, ok := relationships["license"]; ok {
		lic.LicenseID = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	return nil
}

func (lic *MachineFile) Verify() error {
	verifier := &verifier{PublicKey: PublicKey}

	return verifier.VerifyMachineFile(lic)
}

func (lic *MachineFile) Decrypt() (*MachineFileInfo, error) {
	cert, err := lic.certificate()
	if err != nil {
		return nil, err
	}

	if cert.Alg != "aes-256-gcm+ed25519" {
		return nil, ErrLicenseFileNotEncrypted
	}

	// Decrypt
	decryptor := &decryptor{Secret: lic.secret}
	data, err := decryptor.DecryptCertificate(cert)
	if err != nil {
		return nil, err
	}

	// Unmarshal
	info := &MachineFileInfo{}

	if _, err := jsonapi.Unmarshal(data, info); err != nil {
		return nil, err
	}

	return info, nil
}

func (lic *MachineFile) certificate() (*certificate, error) {
	payload := lic.Certificate

	// Remove header and footer
	payload = strings.TrimPrefix(payload, "-----BEGIN MACHINE FILE-----\n")
	payload = strings.TrimSuffix(payload, "-----END MACHINE FILE-----\n")

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

type MachineFileInfo struct {
	Machine      Machine      `json:"-"`
	License      License      `json:"-"`
	Entitlements Entitlements `json:"-"`
	Issued       time.Time    `json:"issued"`
	Expiry       time.Time    `json:"expiry"`
	TTL          int          `json:"ttl"`
}

func (lic *MachineFileInfo) SetData(to func(target interface{}) error) error {
	return to(&lic.Machine)
}

func (lic *MachineFileInfo) SetMeta(to func(target interface{}) error) error {
	return to(&lic)
}

func (lic *MachineFileInfo) SetIncluded(relationships []*jsonapi.ResourceObject, unmarshal func(included *jsonapi.ResourceObject, target interface{}) error) error {
	for _, relationship := range relationships {
		switch relationship.Type {
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
