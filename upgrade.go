package keygen

import "net/url"

type UpgradeOptions struct {
	// CurrentVersion is the current version of the program. This will be used by
	// Keygen to determine if an upgrade is available.
	CurrentVersion string
	// Constraint is a version constraint to use when checking for upgrades. For
	// example, to pin upgrades to v1, you would pass a "1.0" constraint.
	Constraint string
	// Channel is the release channel. One of: stable, rc, beta, alpha or dev.
	Channel string
	// PublicKey is your personal Ed25519ph public key, generated using Keygen's CLI
	// or using ssh-keygen. This will be used to verify the release's signature
	// before install. This MUST NOT be your Keygen account's public key.
	PublicKey string
}

// Upgrade checks if an upgrade is available for the provided version. Returns a
// Release and any errors that occurred, e.g. ErrUpgradeNotAvailable.
func Upgrade(options UpgradeOptions) (*Release, error) {
	if options.PublicKey == PublicKey {
		panic("You MUST use a personal public key. This MUST NOT be your Keygen account's public key.")
	}

	if options.Channel == "" {
		options.Channel = "stable"
	}

	client := &Client{Account: Account, LicenseKey: LicenseKey, Token: Token, PublicKey: PublicKey, UserAgent: UserAgent}
	params := &querystring{Constraint: options.Constraint, Channel: options.Channel}
	release := &Release{}
	version := url.PathEscape(options.CurrentVersion)

	if _, err := client.Get("releases/"+version+"/upgrade", params, release); err != nil {
		switch err.(type) {
		case *NotFoundError:
			return nil, ErrUpgradeNotAvailable
		default:
			return nil, err
		}
	}

	release.publicKey = options.PublicKey

	return release, nil
}
