package keygen

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

type SchemeCode string

const (
	SchemeCodeEd25519 SchemeCode = "ED25519_SIGN"
)

// License represents a Keygen license object.
type License struct {
	ID               string                 `json:"-"`
	Type             string                 `json:"-"`
	Name             string                 `json:"name"`
	Key              string                 `json:"key"`
	Expiry           *time.Time             `json:"expiry"`
	Scheme           SchemeCode             `json:"scheme"`
	RequireHeartbeat bool                   `json:"requireHeartbeat"`
	LastValidated    *time.Time             `json:"lastValidated"`
	Created          time.Time              `json:"created"`
	Updated          time.Time              `json:"updated"`
	Metadata         map[string]interface{} `json:"metadata"`
	PolicyId         string                 `json:"-"`
	LastValidation   *ValidationResult      `json:"-"`
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (l *License) SetID(id string) error {
	l.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (l *License) SetType(t string) error {
	l.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (l *License) SetData(to func(target interface{}) error) error {
	return to(l)
}

// SetRelationships implements the jsonapi.UnmarshalRelationship interface.
func (l *License) SetRelationships(relationships map[string]interface{}) error {
	if relationship, ok := relationships["policy"]; ok {
		l.PolicyId = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	return nil
}

// Validate performs a license validation, scoped to an optional device fingerprint
// and an optional array of hardware component fingerprints. It returns an error
// if the license is invalid, e.g. ErrLicenseNotActivated, ErrLicenseExpired or
// ErrLicenseTooManyMachines.
func (l *License) Validate(ctx context.Context, fingerprints ...string) error {
	client := NewClient()
	validation := &validation{}

	// split up fingerprints (first is machine, rest are components)
	var params validate
	if n := len(fingerprints); n > 0 {
		if n > 1 {
			params = validate{fingerprint: fingerprints[0], components: fingerprints[1:]}
		} else {
			params = validate{fingerprint: fingerprints[0]}
		}
	} else {
		params = validate{}
	}

	if _, err := client.Post(ctx, "licenses/"+l.ID+"/actions/validate", params, validation); err != nil {
		if _, ok := err.(*NotFoundError); ok {
			return ErrLicenseInvalid
		}

		return err
	}

	*l = validation.License

	// Store last validation result
	l.LastValidation = &validation.Result

	if validation.Result.Code == ValidationCodeValid {
		return nil
	}

	switch {
	case validation.Result.Code == ValidationCodeFingerprintScopeMismatch ||
		validation.Result.Code == ValidationCodeNoMachines ||
		validation.Result.Code == ValidationCodeNoMachine:
		return ErrLicenseNotActivated
	case validation.Result.Code == ValidationCodeExpired:
		return ErrLicenseExpired
	case validation.Result.Code == ValidationCodeSuspended:
		return ErrLicenseSuspended
	case validation.Result.Code == ValidationCodeTooManyMachines:
		return ErrLicenseTooManyMachines
	case validation.Result.Code == ValidationCodeTooManyCores:
		return ErrLicenseTooManyCores
	case validation.Result.Code == ValidationCodeTooManyProcesses:
		return ErrLicenseTooManyProcesses
	case validation.Result.Code == ValidationCodeFingerprintScopeRequired ||
		validation.Result.Code == ValidationCodeFingerprintScopeEmpty:
		return ErrValidationFingerprintMissing
	case validation.Result.Code == ValidationCodeComponentsScopeRequired ||
		validation.Result.Code == ValidationCodeComponentsScopeEmpty:
		return ErrValidationComponentsMissing
	case validation.Result.Code == ValidationCodeComponentsScopeMismatch:
		return ErrComponentNotActivated
	case validation.Result.Code == ValidationCodeHeartbeatNotStarted:
		return ErrHeartbeatRequired
	case validation.Result.Code == ValidationCodeHeartbeatDead:
		return ErrHeartbeatDead
	case validation.Result.Code == ValidationCodeProductScopeRequired ||
		validation.Result.Code == ValidationCodeProductScopeEmpty:
		return ErrValidationProductMissing
	default:
		return ErrLicenseInvalid
	}
}

// Verify checks if the license's key is genuine by cryptographically verifying the
// key using your PublicKey. If the license is genuine, the decoded dataset from the
// key will be returned. An error will be returned if the license is not genuine, or
// if the key is not signed, e.g. ErrLicenseNotGenuine or ErrLicenseNotSigned.
func (l *License) Verify() ([]byte, error) {
	if l.Scheme == "" {
		return nil, ErrLicenseNotSigned
	}

	verifier := &verifier{PublicKey: PublicKey}

	return verifier.VerifyLicense(l)
}

// Activate performs a machine activation for the license, identified by the provided
// fingerprint. If the activation is successful, the new machine will be returned. An
// error will be returned if the activation fails, e.g. ErrMachineLimitExceeded
// or ErrMachineAlreadyActivated.
func (l *License) Activate(ctx context.Context, fingerprint string, components ...Component) (*Machine, error) {
	client := NewClient()
	hostname, _ := os.Hostname()
	params := &Machine{
		Fingerprint: fingerprint,
		Hostname:    hostname,
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		Cores:       runtime.NumCPU(),
		LicenseID:   l.ID,
		components:  components,
	}

	machine := &Machine{}
	if _, err := client.Post(ctx, "machines", params, machine); err != nil {
		return nil, err
	}

	return machine, nil
}

// Deactivate performs a machine deactivation, identified by the provided ID. The ID
// can be the machine's UUID or the machine's fingerprint. An error will be returned
// if the machine deactivation fails.
func (l *License) Deactivate(ctx context.Context, id string) error {
	client := NewClient()

	_, err := client.Delete(ctx, "machines/"+id, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

// Machine retreives a machine, identified by the provided ID. The ID can be the machine's
// UUID or the machine's fingerprint. An error will be returned if it does not exist.
func (l *License) Machine(ctx context.Context, id string) (*Machine, error) {
	client := NewClient()
	machine := &Machine{}

	if _, err := client.Get(ctx, "machines/"+id, nil, machine); err != nil {
		return nil, err
	}

	return machine, nil
}

// Machines lists up to 100 machines for the license.
func (l *License) Machines(ctx context.Context) (Machines, error) {
	client := NewClient()
	machines := Machines{}

	if _, err := client.Get(ctx, "licenses/"+l.ID+"/machines", querystring{Limit: 100}, &machines); err != nil {
		return nil, err
	}

	return machines, nil
}

// Machines lists up to 100 entitlements for the license.
func (l *License) Entitlements(ctx context.Context) (Entitlements, error) {
	client := NewClient()
	entitlements := Entitlements{}

	if _, err := client.Get(ctx, "licenses/"+l.ID+"/entitlements", querystring{Limit: 100}, &entitlements); err != nil {
		return nil, err
	}

	return entitlements, nil
}

// Checkout generates an encrypted license file. Returns a LicenseFile.
func (l *License) Checkout(ctx context.Context, options ...CheckoutOption) (*LicenseFile, error) {
	client := NewClient()
	lic := &LicenseFile{}

	opts := CheckoutOptions{Encrypt: true, Include: "entitlements"}
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, err
		}
	}

	if _, err := client.Post(ctx, "licenses/"+l.ID+"/actions/check-out", opts, lic); err != nil {
		return nil, err
	}

	return lic, nil
}
