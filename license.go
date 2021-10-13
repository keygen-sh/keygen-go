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
	client := &Client{account: Account, token: Token}
	params := &Validation{fingerprints}

	res, err := client.Post("licenses/"+l.ID+"/actions/validate", params)
	switch {
	case err == ErrNotFound:
		return ErrLicenseInvalid
	case err != nil:
		return err
	}

	doc, err := jsonapi.Unmarshal(res.Body, &l)
	if err != nil {
		return err
	}

	// FIXME(ezekg) The jsonapi lib doesn't know how to unmarshal document meta
	validation := &ValidationResult{}
	err = json.Unmarshal(doc.Meta, validation)
	if err != nil {
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
	client := &Client{account: Account, token: Token}
	hostname, _ := os.Hostname()
	params := &Machine{
		Fingerprint: fingerprint,
		Hostname:    hostname,
		Platform:    runtime.GOOS + "_" + runtime.GOARCH,
		Cores:       runtime.NumCPU(),
		LicenseID:   l.ID,
	}

	res, err := client.Post("machines", params)
	if err != nil {
		return nil, err
	}

	machine := &Machine{}
	_, err = jsonapi.Unmarshal(res.Body, machine)
	if err != nil {
		return nil, err
	}

	return machine, nil
}

func (l *License) Deactivate(id string) error {
	client := &Client{account: Account, token: Token}

	_, err := client.Delete("machines/"+id, nil)
	if err != nil {
		return err
	}

	return nil
}

func (l *License) Machines() (Machines, error) {
	client := &Client{account: Account, token: Token}

	res, err := client.Get("licenses/"+l.ID+"/machines", nil)
	if err != nil {
		return nil, err
	}

	machines := Machines{}
	_, err = jsonapi.Unmarshal(res.Body, &machines)
	if err != nil {
		return nil, err
	}

	return machines, nil
}

func (l *License) Entitlements() (Entitlements, error) {
	client := &Client{account: Account, token: Token}

	res, err := client.Get("licenses/"+l.ID+"/entitlements", nil)
	if err != nil {
		return nil, err
	}

	entitlements := Entitlements{}
	_, err = jsonapi.Unmarshal(res.Body, &entitlements)
	if err != nil {
		return nil, err
	}

	return entitlements, nil
}
