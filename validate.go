package keygen

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
	ValidationCodeFingerprintScopeRequired ValidationCode = "FINGERPRINT_SCOPE_REQUIRED"
	ValidationCodeFingerprintScopeMismatch ValidationCode = "FINGERPRINT_SCOPE_MISMATCH"
	ValidationCodeFingerprintScopeEmpty    ValidationCode = "FINGERPRINT_SCOPE_EMPTY"
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
	fingerprints []string
}

type meta struct {
	Scope scope `json:"scope"`
}

type scope struct {
	Fingerprints []string `json:"fingerprints"`
	Product      string   `json:"product"`
}

func (v validate) GetMeta() interface{} {
	return meta{Scope: scope{Fingerprints: v.fingerprints, Product: Product}}
}

type validation struct {
	License License `json:"-"`
	Result  result  `json:"-"`
}

func (v *validation) SetData(to func(target interface{}) error) error {
	return to(&v.License)
}

func (v *validation) SetMeta(to func(target interface{}) error) error {
	return to(&v.Result)
}

type result struct {
	Code  ValidationCode `json:"constant"`
	Valid bool           `json:"valid"`
}

// Validate performs a license validation using the current Token, scoped to any
// provided fingerprints. It returns a License, and an error if the license is
// invalid, e.g. ErrLicenseNotActivated or ErrLicenseExpired.
func Validate(fingerprints ...string) (*License, error) {
	client := &Client{Account: Account, LicenseKey: LicenseKey, Token: Token, PublicKey: PublicKey, UserAgent: UserAgent}
	license := &License{}

	if _, err := client.Get("me", nil, license); err != nil {
		return nil, err
	}

	if err := license.Validate(fingerprints...); err != nil {
		return license, err
	}

	return license, nil
}
