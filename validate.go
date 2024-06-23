package keygen

import "context"

type ValidationCode string

const (
	ValidationCodeValid                    ValidationCode = "VALID"
	ValidationCodeNotFound                 ValidationCode = "NOT_FOUND"
	ValidationCodeSuspended                ValidationCode = "SUSPENDED"
	ValidationCodeExpired                  ValidationCode = "EXPIRED"
	ValidationCodeOverdue                  ValidationCode = "OVERDUE"
	ValidationCodeNoMachine                ValidationCode = "NO_MACHINE"
	ValidationCodeNoMachines               ValidationCode = "NO_MACHINES"
	ValidationCodeTooManyMachines          ValidationCode = "TOO_MANY_MACHINES"
	ValidationCodeTooManyCores             ValidationCode = "TOO_MANY_CORES"
	ValidationCodeTooManyProcesses         ValidationCode = "TOO_MANY_PROCESSES"
	ValidationCodeFingerprintScopeRequired ValidationCode = "FINGERPRINT_SCOPE_REQUIRED"
	ValidationCodeFingerprintScopeMismatch ValidationCode = "FINGERPRINT_SCOPE_MISMATCH"
	ValidationCodeFingerprintScopeEmpty    ValidationCode = "FINGERPRINT_SCOPE_EMPTY"
	ValidationCodeComponentsScopeRequired  ValidationCode = "COMPONENTS_SCOPE_REQUIRED"
	ValidationCodeComponentsScopeMismatch  ValidationCode = "COMPONENTS_SCOPE_MISMATCH"
	ValidationCodeComponentsScopeEmpty     ValidationCode = "COMPONENTS_SCOPE_EMPTY"
	ValidationCodeHeartbeatNotStarted      ValidationCode = "HEARTBEAT_NOT_STARTED"
	ValidationCodeHeartbeatDead            ValidationCode = "HEARTBEAT_DEAD"
	ValidationCodeProductScopeRequired     ValidationCode = "PRODUCT_SCOPE_REQUIRED"
	ValidationCodeProductScopeEmpty        ValidationCode = "PRODUCT_SCOPE_MISMATCH"
	ValidationCodePolicyScopeRequired      ValidationCode = "POLICY_SCOPE_REQUIRED"
	ValidationCodePolicyScopeMismatch      ValidationCode = "POLICY_SCOPE_MISMATCH"
	ValidationCodeMachineScopeRequired     ValidationCode = "MACHINE_SCOPE_REQUIRED"
	ValidationCodeMachineScopeMismatch     ValidationCode = "MACHINE_SCOPE_MISMATCH"
	ValidationCodeEntitlementsMissing      ValidationCode = "ENTITLEMENTS_MISSING"
	ValidationCodeEntitlementsEmpty        ValidationCode = "ENTITLEMENTS_SCOPE_EMPTY"
)

type validate struct {
	fingerprint string
	components  []string
}

type meta struct {
	Scope scope `json:"scope"`
}

type scope struct {
	Fingerprint string   `json:"fingerprint,omitempty"`
	Components  []string `json:"components,omitempty"`
	Product     string   `json:"product"`
	Environment *string  `json:"environment,omitempty"`
}

// GetMeta implements jsonapi.MarshalMeta interface.
func (v validate) GetMeta() interface{} {
	if Environment != "" {
		return meta{Scope: scope{Fingerprint: v.fingerprint, Components: v.components, Product: Product, Environment: &Environment}}
	}

	return meta{Scope: scope{Fingerprint: v.fingerprint, Components: v.components, Environment: nil, Product: Product}}
}

type validation struct {
	License License          `json:"-"`
	Result  ValidationResult `json:"-"`
}

// SetData implements the jsonapi.UnmarshalData interface.
func (v *validation) SetData(to func(target interface{}) error) error {
	return to(&v.License)
}

// SetMeta implements jsonapi.UnmarshalMeta interface.
func (v *validation) SetMeta(to func(target interface{}) error) error {
	return to(&v.Result)
}

// ValidationResult contains the scopes for a validation.
type ValidationScope struct {
	scope
}

// ValidationResult is the result of the validation.
type ValidationResult struct {
	Detail string           `json:"detail"`
	Valid  bool             `json:"valid"`
	Code   ValidationCode   `json:"code"`
	Scope  *ValidationScope `json:"scope,omitempty"`
}

// Validate performs a license validation using the current Token, scoped to any
// provided fingerprints. The first fingerprint should be a machine fingerprint,
// and the rest are optional component fingerprints. It returns a License, and
// an error if the license is invalid, e.g. ErrLicenseNotActivated or
// ErrLicenseExpired.
func Validate(ctx context.Context, fingerprints ...string) (*License, error) {
	client := NewClient()
	license := &License{}

	if _, err := client.Get(ctx, "me", nil, license); err != nil {
		return nil, err
	}

	if err := license.Validate(ctx, fingerprints...); err != nil {
		return license, err
	}

	return license, nil
}
