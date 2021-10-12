package keygen

import (
	"github.com/pieoneers/jsonapi-go"
)

// Account is the Keygen account ID used globally in the binding.
var Account string

// Product is the Keygen product ID used globally in the binding.
var Product string

// Token is the Keygen API token used globally in the binding.
var Token string

func Validate(fingerprints ...string) (*License, error) {
	cli := &client{account: Account, token: Token}
	res, err := cli.Get("me", nil)
	if err != nil {
		return nil, err
	}

	license := &License{}
	_, err = jsonapi.Unmarshal(res.Body, license)
	if err != nil {
		return nil, err
	}

	err = license.Validate(fingerprints...)
	if err != nil {
		return license, err
	}

	return license, nil
}

func Upgrade() {

}
