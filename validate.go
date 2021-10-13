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
	Code  ValidationCode `json:"constant"`
	Valid bool           `json:"valid"`
}

func Validate(fingerprints ...string) (*License, error) {
	client := &Client{Account: Account, Token: Token}
	license := &License{}

	if _, err := client.Get("me", nil, license); err != nil {
		return nil, err
	}

	if err := license.Validate(fingerprints...); err != nil {
		return license, err
	}

	return license, nil
}
