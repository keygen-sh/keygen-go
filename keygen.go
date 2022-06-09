package keygen

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// The current version of the SDK.
	SDKVersion = "2.0.0-beta.5"
)

var (
	// APIURL is the URL of the API service backend.
	APIURL = "https://api.keygen.sh"

	// APIVersion is the currently supported API version.
	APIVersion = "1.1"

	// APIPrefix is the major version prefix included in all API URLs.
	APIPrefix = "v1"

	// Account is the Keygen account ID used globally in the binding.
	Account string

	// Product is the Keygen product ID used globally in the binding.
	Product string

	// LicenseKey is the end-user's license key used in the binding.
	LicenseKey string

	// Token is the end-user's API token used in the binding.
	Token string

	// PublicKey is the Keygen public key used for verifying license keys
	// and API response signatures.
	PublicKey string

	// UserAgent defines the user-agent string sent to the API backend,
	// uniquely identifying an integration.
	UserAgent string

	// Logger is a leveled logger implementation used for printing debug,
	// informational, warning, and error messages.
	Logger LoggerInterface = &LeveledLogger{Level: LogLevelError}

	// Program is the name of the current program, used when installing
	// upgrades. Defaults to the current program name.
	Program = filepath.Base(os.Args[0])

	// MaxClockDrift is the maximum allowable difference between the
	// server time Keygen's API sent a request or response and the
	// current system time, to prevent replay attacks.
	MaxClockDrift = time.Duration(5) * time.Minute
)
