package keygen

const (
	ValidationCodeValid                    = "VALID"
	ValidationCodeNotFound                 = "NOT_FOUND"
	ValidationCodeSuspended                = "SUSPENDED"
	ValidationCodeExpired                  = "EXPIRED"
	ValidationCodeOverdue                  = "OVERDUE"
	ValidationCodeNoMachine                = "NO_MACHINE"
	ValidationCodeNoMachines               = "NO_MACHINES"
	ValidationCodeTooManyMachines          = "TOO_MANY_MACHINES"
	ValidationCodeTooManyCores             = "TOO_MANY_CORES"
	ValidationCodeFingerprintScopeRequired = "FINGERPRINT_SCOPE_REQUIRED"
	ValidationCodeFingerprintScopeMismatch = "FINGERPRINT_SCOPE_MISMATCH"
	ValidationCodeFingerprintScopeEmpty    = "FINGERPRINT_SCOPE_EMPTY"
	ValidationCodeProductScopeRequired     = "PRODUCT_SCOPE_REQUIRED"
	ValidationCodeProductScopeEmpty        = "PRODUCT_SCOPE_MISMATCH"
	ValidationCodePolicyScopeRequired      = "POLICY_SCOPE_REQUIRED"
	ValidationCodePolicyScopeMismatch      = "POLICY_SCOPE_MISMATCH"
	ValidationCodeMachineScopeRequired     = "MACHINE_SCOPE_REQUIRED"
	ValidationCodeMachineScopeMismatch     = "MACHINE_SCOPE_MISMATCH"
	ValidationCodeEntitlementsMissing      = "ENTITLEMENTS_MISSING"
	ValidationCodeEntitlementsEmpty        = "ENTITLEMENTS_SCOPE_EMPTY"
)

type Validation struct {
	fingerprints []string
}

type ValidationMeta struct {
	Scope ValidationScope `json:"scope"`
}

type ValidationScope struct {
	Fingerprints []string `json:"fingerprints"`
	Product      string   `json:"product"`
}

func (v Validation) GetMeta() interface{} {
	return ValidationMeta{Scope: ValidationScope{Fingerprints: v.fingerprints, Product: Product}}
}

type ValidationResult struct {
	Code  string `json:"constant"`
	Valid bool   `json:"valid"`
}
