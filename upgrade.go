package keygen

import (
	"errors"
	"net/http"
)

var (
	ErrUpgradeNotAvailable = errors.New("no upgrades available (already up-to-date)")
)

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

// Upgrade checks if an upgrade is available for the provided version.
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

	res, err := client.Get("releases/"+options.CurrentVersion+"/upgrade", params, release)
	if err != nil {
		return nil, err
	}

	if res.Status == http.StatusNotFound {
		return nil, ErrUpgradeNotAvailable
	}

	release.publicKey = options.PublicKey

	return release, nil
}
