package keygen

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/keygen-sh/go-update"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

var (
	ErrReleaseLocationMissing = errors.New("release has no download URL")
)

// Release represents a Keygen release object.
type Release struct {
	ID          string                 `json:"-"`
	Type        string                 `json:"-"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Filename    string                 `json:"filename"`
	Filetype    string                 `json:"filetype"`
	Filesize    int64                  `json:"filesize"`
	Platform    string                 `json:"platform"`
	Channel     string                 `json:"channel"`
	Signature   string                 `json:"signature"`
	Checksum    string                 `json:"checksum"`
	Created     time.Time              `json:"created"`
	Updated     time.Time              `json:"updated"`
	Metadata    map[string]interface{} `json:"metadata"`
	Location    string                 `json:"-"`
}

// Implement jsonapi.UnmarshalData interface
func (r *Release) SetID(id string) error {
	r.ID = id
	return nil
}

func (r *Release) SetType(t string) error {
	r.Type = t
	return nil
}

func (r *Release) SetData(to func(target interface{}) error) error {
	return to(r)
}

// Install performs an update of the current executable to the new Release.
func (r *Release) Install() error {
	if r.Location == "" {
		return ErrReleaseLocationMissing
	}

	res, err := http.Get(r.Location)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	opts := update.Options{}

	if s := r.Signature; s != "" {
		if k := UpgradeKey; k != "" {
			opts.Signature, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return err
			}

			opts.Verifier = ed25519phVerifier{}
			opts.PublicKey = k
		}
	}

	if c := r.Checksum; c != "" {
		opts.Checksum, err = base64.RawStdEncoding.DecodeString(c)
		if err != nil {
			return err
		}

		opts.Hash = crypto.SHA512
	}

	err = update.Apply(res.Body, opts)
	if err != nil {
		return err
	}

	return nil
}

type ed25519phVerifier struct{}

func (v ed25519phVerifier) VerifySignature(checksum []byte, signature []byte, _ crypto.Hash, publicKey crypto.PublicKey) error {
	opts := &ed25519.Options{Hash: crypto.SHA512}
	key, err := hex.DecodeString(publicKey.(string))
	if err != nil {
		return errors.New("failed to decode ed25519ph public key")
	}

	if l := len(key); l != ed25519.PublicKeySize {
		return errors.New("invalid ed25519ph public key")
	}

	if ok := ed25519.VerifyWithOptions(key, checksum, signature, opts); !ok {
		return errors.New("failed to verify ed25519ph signature")
	}

	return nil
}
