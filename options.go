package keygen

import (
	"strings"
	"time"
)

type CheckoutAlgorithmCode string

const (
	CheckoutAlgorithmCodeEd25519 CheckoutAlgorithmCode = "ed25519"
	CheckoutAlgorithmCodeP256    CheckoutAlgorithmCode = "ecdsa-p256"
)

type CheckoutOptions struct {
	Encrypt   bool                  `url:"encrypt"`
	Algorithm CheckoutAlgorithmCode `url:"algorithm,omitempty"`
	Include   string                `url:"include,omitempty"`
	TTL       int                   `url:"ttl,omitempty"`
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

func CheckoutAlgorithm(algorithm CheckoutAlgorithmCode) CheckoutOption {
	return func(options *CheckoutOptions) error {
		options.Algorithm = algorithm

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
