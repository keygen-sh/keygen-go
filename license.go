package keygen

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"
)

var (
	ErrLicenseNotActivated    = errors.New("license is not activated")
	ErrLicenseExpired         = errors.New("license is expired")
	ErrLicenseSuspended       = errors.New("license is suspended")
	ErrLicenseTooManyMachines = errors.New("license has too many machines")
	ErrLicenseTooManyCores    = errors.New("license has too many cores")
	ErrLicenseNotSigned       = errors.New("license is not signed")
	ErrLicenseInvalid         = errors.New("license is invalid")
)

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

func (l *License) Validate(fingerprints ...string) error {
	client := &Client{Account: Account, Token: Token}
	params := &Validation{fingerprints}

	res, err := client.Post("licenses/"+l.ID+"/actions/validate", params, &l)
	switch {
	case err == ErrNotFound:
		return ErrLicenseInvalid
	case err != nil:
		return err
	}

	// FIXME(ezekg) The jsonapi lib doesn't know how to unmarshal document meta
	validation := &ValidationResult{}
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
	default:
		return ErrLicenseInvalid
	}
}

func (l *License) Genuine() ([]byte, error) {
	if l.Scheme == "" {
		return nil, ErrLicenseNotSigned
	}

	return Genuine(l.Key, l.Scheme)
}

func (l *License) Activate(fingerprint string) (*Machine, error) {
	client := &Client{Account: Account, Token: Token}
	hostname, _ := os.Hostname()
	params := &Machine{
		Fingerprint: fingerprint,
		Hostname:    hostname,
		Platform:    runtime.GOOS + "_" + runtime.GOARCH,
		Cores:       runtime.NumCPU(),
		LicenseID:   l.ID,
	}

	machine := &Machine{}
	if _, err := client.Post("machines", params, machine); err != nil {
		return nil, err
	}

	return machine, nil
}

func (l *License) Deactivate(id string) error {
	client := &Client{Account: Account, Token: Token}

	_, err := client.Delete("machines/"+id, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (l *License) Machines() (Machines, error) {
	client := &Client{Account: Account, Token: Token}
	machines := Machines{}

	if _, err := client.Get("licenses/"+l.ID+"/machines", nil, &machines); err != nil {
		return nil, err
	}

	return machines, nil
}

func (l *License) Entitlements() (Entitlements, error) {
	client := &Client{Account: Account, Token: Token}
	entitlements := Entitlements{}

	if _, err := client.Get("licenses/"+l.ID+"/entitlements", nil, &entitlements); err != nil {
		return nil, err
	}

	return entitlements, nil
}
