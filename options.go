package keygen

import (
	"strings"
	"time"
)

type CheckoutOptions struct {
	Algorithm string `url:"algorithm,omitempty"`
	Include   string `url:"include,omitempty"`
	TTL       int    `url:"ttl,omitempty"`

	// these are mainly used to build up algorithm prior to checkout
	Encrypt bool   `url:"encrypt"`
	Sign    string `url:"-"`
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

func CheckoutEncrypt(encrypt bool) CheckoutOption {
	return func(options *CheckoutOptions) error {
		options.Encrypt = encrypt

		return nil
	}
}

func CheckoutAlgorithm(algorithm SigningAlgorithm) CheckoutOption {
	return func(options *CheckoutOptions) error {
		options.Sign = string(algorithm)

		return nil
	}
}

type VerifyOption func(*verifier) error

func VerifyPublicKey(key string) VerifyOption {
	return func(verifier *verifier) error {
		verifier.PublicKey = key

		return nil
	}
}
