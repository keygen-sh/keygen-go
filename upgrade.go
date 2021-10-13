package keygen

import (
	"errors"
	"net/http"
	"runtime"
)

var (
	ErrUpgradeNotAvailable = errors.New("no upgrades available (already up-to-date)")
)

type SemanticVersion string

type UpgradeParams struct {
	Product  string          `url:"product"`
	Version  SemanticVersion `url:"version"`
	Platform string          `url:"platform"`
	Channel  string          `url:"channel"`
	Filetype string          `url:"filetype"`
}

func Upgrade(currentVersion SemanticVersion) (*Release, error) {
	client := &Client{Account: Account, Token: Token}
	params := &UpgradeParams{Product: Product, Version: currentVersion, Platform: runtime.GOOS + "_" + runtime.GOARCH, Channel: "stable", Filetype: "binary"}
	artifact := &Artifact{}

	res, err := client.Get("releases/actions/upgrade", params, artifact)
	if err != nil {
		return nil, err
	}

	if res.Status == http.StatusNoContent {
		return nil, ErrUpgradeNotAvailable
	}

	release, err := artifact.Release()
	if err != nil {
		return nil, err
	}

	// Add download location to upgrade
	release.Location = res.Headers.Get("Location")

	return release, nil
}
