package keygen

import "runtime"

var (
	// Account is the Keygen account ID used globally in the binding.
	Account string

	// Product is the Keygen product ID used globally in the binding.
	Product string

	// Token is the Keygen API token used globally in the binding.
	Token string

	// PublicKey is the Keygen public key used for verifying license keys
	// and API response signatures.
	PublicKey string

	// Channel is the release channel used when checking for upgrades.
	Channel = "stable"
)

const (
	// Platform is the release platform used when checking for upgrades
	// and when activating machines.
	Platform = runtime.GOOS + "_" + runtime.GOARCH
)
