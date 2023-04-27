package keygen

import (
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-cleanhttp"
)

const (
	// The current version of the SDK.
	SDKVersion = "2.4.1"
)

var (
	// APIURL is the URL of the API service backend.
	APIURL = "https://api.keygen.sh"

	// APIVersion is the currently supported API version.
	APIVersion = "1.2"

	// APIPrefix is the major version prefix included in all API URLs.
	APIPrefix = "v1"

	// Account is the Keygen account ID used globally in the SDK.
	Account string

	// Product is the Keygen product ID used globally in the SDK.
	Product string

	// LicenseKey is the end-user's license key used in the SDK.
	LicenseKey string

	// Token is the end-user's API token used in the SDK.
	Token string

	// PublicKey is the Keygen public key used for verifying license keys
	// and API response signatures.
	PublicKey string

	// UserAgent defines the user-agent string sent to the API backend,
	// uniquely identifying an integration.
	UserAgent string

	// Logger is a leveled logger implementation used for printing debug,
	// informational, warning, and error messages.
	Logger LeveledLogger = &logger{Level: LogLevelError}

	// Program is the name of the current program, used when installing
	// upgrades. Defaults to the current program name.
	Program = filepath.Base(os.Args[0])

	// MaxClockDrift is the maximum allowable difference between the
	// server time Keygen's API sent a request or response and the
	// current system time, to prevent clock-tampering and replay
	// attacks. Set to -1 to disable.
	MaxClockDrift = time.Duration(5) * time.Minute

	// HTTPClient is the internal HTTP client used by the SDK for API
	// requests. Set this to a custom HTTP client, to implement e.g.
	// automatic retries, rate limiting checks, or for tests.
	HTTPClient = cleanhttp.DefaultPooledClient()
)
