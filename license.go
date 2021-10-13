package keygen

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/pieoneers/jsonapi-go"
)

var (
	ErrLicenseNotActivated    = errors.New("license is not activated")
	ErrLicenseExpired         = errors.New("license is expired")
	ErrLicenseSuspended       = errors.New("license is suspended")
	ErrLicenseTooManyMachines = errors.New("license has too many machines")
	ErrLicenseTooManyCores    = errors.New("license has too many cores")
	ErrLicenseNotSigned       = errors.New("license is not signed")
	ErrLicenseInvalid         = errors.New("license is invalid")
	ErrFingerprintMissing     = errors.New("fingerprint scope is missing")
	ErrProductMissing         = errors.New("product scope is missing")
)

// License represents a Keygen license object.
type License struct {
	ID            string                 `json:"-"`
	Type          string                 `json:"-"`
	Name          string                 `json:"name"`
	Key           string                 `json:"key"`
	Expiry        *time.Time             `json:"expiry"`
	Scheme        string                 `json:"scheme"`
	LastValidated *time.Time             `json:"lastValidated"`
	Created       time.Time              `json:"created"`
	Updated       time.Time              `json:"updated"`
	Metadata      map[string]interface{} `json:"metadata"`
	PolicyId      string                 `json:"-"`
}

// Implement jsonapi.UnmarshalData interface
func (l *License) SetID(id string) error {
	l.ID = id
	return nil
}

func (l *License) SetType(t string) error {
	l.Type = t
	return nil
}

func (l *License) SetData(to func(target interface{}) error) error {
	return to(l)
}

func (l *License) SetRelationships(relationships map[string]interface{}) error {
	if relationship, ok := relationships["policy"]; ok {
		l.PolicyId = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	return nil
}

type limit struct {
	Limit int `url:"limit"`
}

// Validate performs a license validation, scoped to any provided fingerprints. It
// returns an error if the license is invalid, e.g. ErrLicenseNotActivated,
// ErrLicenseExpired or ErrLicenseTooManyMachines.
func (l *License) Validate(fingerprints ...string) error {
	client := &Client{Account: Account, Token: Token}
	params := &validate{fingerprints}

	res, err := client.Post("licenses/"+l.ID+"/actions/validate", params, &l)
	switch {
	case err == ErrNotFound:
		return ErrLicenseInvalid
	case err != nil:
		return err
	}

	// FIXME(ezekg) The jsonapi lib doesn't know how to unmarshal document meta
	validation := &validation{}
	if err := json.Unmarshal(res.Document.Meta, validation); err != nil {
		return err
	}

	switch {
	case validation.Code == ValidationCodeFingerprintScopeMismatch ||
		validation.Code == ValidationCodeNoMachines ||
		validation.Code == ValidationCodeNoMachine:
		return ErrLicenseNotActivated
	case validation.Code == ValidationCodeExpired:
		return ErrLicenseExpired
	case validation.Code == ValidationCodeSuspended:
		return ErrLicenseSuspended
	case validation.Code == ValidationCodeTooManyMachines:
		return ErrLicenseTooManyMachines
	case validation.Code == ValidationCodeTooManyCores:
		return ErrLicenseTooManyCores
	case validation.Code == ValidationCodeFingerprintScopeRequired ||
		validation.Code == ValidationCodeFingerprintScopeEmpty:
		return ErrFingerprintMissing
	case validation.Code == ValidationCodeProductScopeRequired ||
		validation.Code == ValidationCodeProductScopeEmpty:
		return ErrProductMissing
	default:
		return ErrLicenseInvalid
	}
}

// Genuine checks if the license's key is genuine by cryptographically verifying the
// key using your PublicKey. If the license is genuine, the decoded dataset from the
// key will be returned. An error will be returned if the license is not genuine, or
// if the key is not signed, e.g. ErrLicenseNotGenuine or ErrLicenseNotSigned.
func (l *License) Genuine() ([]byte, error) {
	if l.Scheme == "" {
		return nil, ErrLicenseNotSigned
	}

	return Genuine(l.Key, l.Scheme)
}

// Activate performs a machine activation for the license, identified by the provided
// fingerprint. If the activation is successful, the new machine will be returned. An
// error will be returned if the activation fails, e.g. ErrMachineLimitExceeded
// or ErrMachineAlreadyActivated.
func (l *License) Activate(fingerprint string) (*Machine, error) {
	client := &Client{Account: Account, Token: Token}
	hostname, _ := os.Hostname()
	params := &Machine{
		Fingerprint: fingerprint,
		Hostname:    hostname,
		Platform:    Platform,
		Cores:       runtime.NumCPU(),
		LicenseID:   l.ID,
	}

	machine := &Machine{}
	if _, err := client.Post("machines", params, machine); err != nil {
		return nil, err
	}

	return machine, nil
}

// Deactivate performs a machine deactivation, identified by the provided ID. The ID
// can be the machine's UUID or the machine's fingerprint. An error will be returned
// if the machine deactivation fails.
func (l *License) Deactivate(id string) error {
	client := &Client{Account: Account, Token: Token}

	_, err := client.Delete("machines/"+id, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

// Machines lists up to 100 machines for the license.
func (l *License) Machines() (Machines, error) {
	client := &Client{Account: Account, Token: Token}
	machines := Machines{}

	if _, err := client.Get("licenses/"+l.ID+"/machines", limit{100}, &machines); err != nil {
		return nil, err
	}

	return machines, nil
}

// Machines lists up to 100 entitlements for the license.
func (l *License) Entitlements() (Entitlements, error) {
	client := &Client{Account: Account, Token: Token}
	entitlements := Entitlements{}

	if _, err := client.Get("licenses/"+l.ID+"/entitlements", limit{100}, &entitlements); err != nil {
		return nil, err
	}

	return entitlements, nil
}
