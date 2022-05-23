package keygen

import (
	"errors"
	"net/http"
)

var (
	ErrUpgradeNotAvailable = errors.New("no upgrades available (already up-to-date)")
)

// Upgrade checks if an upgrade is available for the provided version.
func Upgrade(version string) (*Release, error) {
	client := &Client{Account: Account, LicenseKey: LicenseKey, Token: Token, PublicKey: PublicKey, UserAgent: UserAgent}
	release := &Release{}

	res, err := client.Get("releases/"+version+"/upgrade", nil, release)
	if err != nil {
		return nil, err
	}

	if res.Status == http.StatusNotFound {
		return nil, ErrUpgradeNotAvailable
	}

	return release, nil
}
