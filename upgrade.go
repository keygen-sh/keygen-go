package keygen

import (
	"errors"
	"net/http"
)

var (
	ErrUpgradeNotAvailable = errors.New("no upgrades available (already up-to-date)")
)

type upgrade struct {
	Product  string `url:"product"`
	Version  string `url:"version"`
	Platform string `url:"platform"`
	Channel  string `url:"channel"`
	Filetype string `url:"filetype"`
}

func Upgrade(currentVersion string) (*Release, error) {
	client := &Client{Account: Account, LicenseKey: LicenseKey, Token: Token, PublicKey: PublicKey, UserAgent: UserAgent}
	params := &upgrade{Product: Product, Version: currentVersion, Platform: Platform, Channel: Channel, Filetype: Filetype}
	artifact := &Artifact{}

	res, err := client.Get("releases/actions/upgrade", params, artifact)
	if err != nil {
		return nil, err
	}

	if res.Status == http.StatusNoContent {
		return nil, ErrUpgradeNotAvailable
	}

	release, err := artifact.release()
	if err != nil {
		return nil, err
	}

	// Add download location to upgrade
	release.Location = res.Headers.Get("Location")

	return release, nil
}
