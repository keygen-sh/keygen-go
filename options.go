package keygen

import (
	"strings"
	"time"
)

type CheckoutOptions struct {
	Encrypt bool   `url:"encrypt"`
	Include string `url:"include,omitempty"`
	TTL     int    `url:"ttl,omitempty"`
}

type CheckoutOption func(*CheckoutOptions) error

func CheckoutInclude(includes ...string) CheckoutOption {
	return func(options *CheckoutOptions) error {
		options.Include = strings.Join(includes, ",")

		return nil
	}
}

func CheckoutTTL(ttl time.Duration) CheckoutOption {
	return func(options *CheckoutOptions) error {
		options.TTL = int(ttl.Seconds())

		return nil
	}
}
