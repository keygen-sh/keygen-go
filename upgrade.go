package keygen

import (
	"errors"
	"net/http"
	"runtime"

	"github.com/pieoneers/jsonapi-go"
)

var (
	ErrUpgradeNotAvailable = errors.New("no upgrades available (already up-to-date)")
)

type UpgradeParams struct {
	Product  string `url:"product"`
	Version  string `url:"version"`
	Platform string `url:"platform"`
	Channel  string `url:"channel"`
	Filetype string `url:"filetype"`
}

func Upgrade(currentVersion string) (*Release, error) {
	cli := &client{account: Account, token: Token}
	params := &UpgradeParams{Product: Product, Version: currentVersion, Platform: runtime.GOOS + "-" + runtime.GOARCH, Channel: "stable", Filetype: "binary"}
	res, err := cli.Get("releases/actions/upgrade", params)
	if err != nil {
		return nil, err
	}

	if res.Status == http.StatusNoContent {
		return nil, ErrUpgradeNotAvailable
	}

	artifact := &Artifact{}
	_, err = jsonapi.Unmarshal(res.Body, artifact)
	if err != nil {
		return nil, err
	}

	release, err := artifact.Release()
	if err != nil {
		return nil, err
	}

	// Add download location to upgrade
	release.Location = res.Headers.Get("Location")

	return release, nil
}
