package keygen

import (
	"os"
	"path/filepath"
)

const (
	// The current version of the SDK.
	SDKVersion = "2.0.0-beta.1"
)

var (
	// APIURL is the URL of the API service backend.
	APIURL = "https://api.keygen.sh"

	// APIVersion is the currently supported API version.
	APIVersion = "1.1"

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

	// Executable is the name of the current program, used when installing
	// upgrades.
	Executable = filepath.Base(os.Args[0])

	// UserAgent defines the user-agent string sent to the API backend,
	// uniquely identifying an integration.
	UserAgent string

	// Logger is a leveled logger implementation used for printing debug,
	// informational, warning, and error messages.
	Logger LoggerInterface = &LeveledLogger{Level: LogLevelError}
)
