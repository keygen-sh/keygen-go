package keygen

import (
	"errors"
	"fmt"
	"time"
)

// ErrorCode defines various error codes that are handled explicitly.
type ErrorCode string

const (
	ErrorCodeTokenInvalid         ErrorCode = "TOKEN_INVALID"
	ErrorCodeLicenseInvalid       ErrorCode = "LICENSE_INVALID"
	ErrorCodeFingerprintTaken     ErrorCode = "FINGERPRINT_TAKEN"
	ErrorCodeMachineLimitExceeded ErrorCode = "MACHINE_LIMIT_EXCEEDED"
	ErrorCodeProcessLimitExceeded ErrorCode = "MACHINE_PROCESS_LIMIT_EXCEEDED"
	ErrorCodeMachineHeartbeatDead ErrorCode = "MACHINE_HEARTBEAT_DEAD"
	ErrorCodeProcessHeartbeatDead ErrorCode = "PROCESS_HEARTBEAT_DEAD"
	ErrorCodeNotFound             ErrorCode = "NOT_FOUND"
)

// Error represents an API error response.
type Error struct {
	Response *Response
	Title    string
	Detail   string
	Code     string
	Source   string
}

func (e *Error) Error() string {
	res := e.Response

	return fmt.Sprintf("an error occurred: id=%s status=%d size=%d body=%s", res.ID, res.Status, res.Size, res.tldr())
}

// LicenseTokenError represents an API authentication error due to an invalid license token.
type LicenseTokenError struct{ Err *Error }

func (e *LicenseTokenError) Error() string { return "license token is invalid" }
func (e *LicenseTokenError) Unwrap() error { return e.Err }

// LicenseKeyError represents an API authentication error due to an invalid license key.
type LicenseKeyError struct{ Err *Error }

func (e *LicenseKeyError) Error() string { return "license key is invalid" }
func (e *LicenseKeyError) Unwrap() error { return e.Err }

// NotAuthorizedError represents an API permission error.
type NotAuthorizedError struct{ Err *Error }

func (e *NotAuthorizedError) Error() string { return "not authorized to perform the request" }
func (e *NotAuthorizedError) Unwrap() error { return e.Err }

// NotFoundError represents an API not found error.
type NotFoundError struct{ Err *Error }

func (e *NotFoundError) Error() string { return "resource was not found" }
func (e *NotFoundError) Unwrap() error { return e.Err }

// LicenseFileError represents an invalid license file error.
type LicenseFileError struct{ Err error }

func (e *LicenseFileError) Error() string { return "license file is invalid" }
func (e *LicenseFileError) Unwrap() error { return e.Err }

// MachineFileError represents an invalid machine file error.
type MachineFileError struct{ Err error }

func (e *MachineFileError) Error() string { return "machine file is invalid" }
func (e *MachineFileError) Unwrap() error { return e.Err }

// RateLimitError represents an API rate limiting error.
type RateLimitError struct {
	Window     string
	Count      int
	Limit      int
	Remaining  int
	Reset      time.Time
	RetryAfter int
	Err        error
}

func (e *RateLimitError) Error() string { return "rate limit has been exceeded" }
func (e *RateLimitError) Unwrap() error { return e.Err }

// General errors
var (
	ErrReleaseLocationMissing       = errors.New("release has no download URL")
	ErrUpgradeNotAvailable          = errors.New("no upgrades available (already up-to-date)")
	ErrResponseSignatureMissing     = errors.New("response signature is missing")
	ErrResponseSignatureInvalid     = errors.New("response signature is invalid")
	ErrResponseDigestMissing        = errors.New("response digest is missing")
	ErrResponseDigestInvalid        = errors.New("response digest is invalid")
	ErrResponseDateInvalid          = errors.New("response date is invalid")
	ErrResponseDateTooOld           = errors.New("response date is too old")
	ErrPublicKeyMissing             = errors.New("public key is missing")
	ErrPublicKeyInvalid             = errors.New("public key is invalid")
	ErrValidationFingerprintMissing = errors.New("validation fingerprint scope is missing")
	ErrValidationProductMissing     = errors.New("validation product scope is missing")
	ErrHeartbeatPingFailed          = errors.New("heartbeat ping failed")
	ErrHeartbeatRequired            = errors.New("heartbeat is required")
	ErrHeartbeatDead                = errors.New("heartbeat is dead")
	ErrMachineAlreadyActivated      = errors.New("machine is already activated")
	ErrMachineLimitExceeded         = errors.New("machine limit has been exceeded")
	ErrMachineNotFound              = errors.New("machine no longer exists")
	ErrProcessNotFound              = errors.New("process no longer exists")
	ErrMachineFileNotSupported      = errors.New("machine file is not supported")
	ErrMachineFileNotEncrypted      = errors.New("machine file is not encrypted")
	ErrMachineFileNotGenuine        = errors.New("machine file is not genuine")
	ErrMachineFileExpired           = errors.New("machine file is expired")
	ErrProcessLimitExceeded         = errors.New("process limit has been exceeded")
	ErrLicenseSchemeNotSupported    = errors.New("license scheme is not supported")
	ErrLicenseSchemeMissing         = errors.New("license scheme is missing")
	ErrLicenseKeyMissing            = errors.New("license key is missing")
	ErrLicenseKeyNotGenuine         = errors.New("license key is not genuine")
	ErrLicenseNotActivated          = errors.New("license is not activated")
	ErrLicenseExpired               = errors.New("license is expired")
	ErrLicenseSuspended             = errors.New("license is suspended")
	ErrLicenseTooManyMachines       = errors.New("license has too many machines")
	ErrLicenseTooManyCores          = errors.New("license has too many cores")
	ErrLicenseNotSigned             = errors.New("license is not signed")
	ErrLicenseInvalid               = errors.New("license is invalid")
	ErrLicenseFileNotSupported      = errors.New("license file is not supported")
	ErrLicenseFileNotEncrypted      = errors.New("license file is not encrypted")
	ErrLicenseFileNotGenuine        = errors.New("license file is not genuine")
	ErrLicenseFileExpired           = errors.New("license file is expired")
	ErrLicenseFileSecretMissing     = errors.New("license file secret is missing")
	ErrSystemClockUnsynced          = errors.New("system clock is out of sync")
)
