package keygen

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"runtime"
	"text/template"
	"time"

	"github.com/keygen-sh/go-update"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
)

// Release represents a Keygen release object.
type Release struct {
	ID          string                 `json:"-"`
	Type        string                 `json:"-"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Channel     string                 `json:"channel"`
	Created     time.Time              `json:"created"`
	Updated     time.Time              `json:"updated"`
	Metadata    map[string]interface{} `json:"metadata"`

	opts UpgradeOptions `json:"-"`
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (r *Release) SetID(id string) error {
	r.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (r *Release) SetType(t string) error {
	r.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (r *Release) SetData(to func(target interface{}) error) error {
	return to(r)
}

// Install performs an update of the current executable to the new Release.
func (r *Release) Install() error {
	artifact, err := r.artifact()
	if err != nil {
		return err
	}

	res, err := http.Get(artifact.URL)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	opts := update.Options{}

	if s := artifact.Signature; s != "" {
		if k := r.opts.PublicKey; k != "" {
			opts.Signature, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return err
			}

			opts.Verifier = ed25519phVerifier{}
			opts.PublicKey = k
		}
	}

	if c := artifact.Checksum; c != "" {
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

func (r *Release) artifact() (*Artifact, error) {
	client := &Client{Account: Account, LicenseKey: LicenseKey, Token: Token, PublicKey: PublicKey, UserAgent: UserAgent}
	artifact := &Artifact{}

	filename, err := r.filename()
	if err != nil {
		return nil, err
	}

	res, err := client.Get("releases/"+r.ID+"/artifacts/"+filename, nil, artifact)
	if err != nil {
		return nil, err
	}

	// Add download URL to artifact
	artifact.URL = res.Headers.Get("Location")

	return artifact, nil
}

func (r *Release) filename() (string, error) {
	tmpl, err := template.New("").Parse(r.opts.Filename)
	if err != nil {
		return "", err
	}

	in := map[string]string{"program": Program, "ext": Ext, "platform": runtime.GOOS, "arch": runtime.GOARCH, "channel": r.Channel, "version": r.Version}
	var out bytes.Buffer

	if err := tmpl.Execute(&out, in); err != nil {
		return "", err
	}

	return out.String(), nil
}

// ed25519phVerifier handles verifying the upgrade's signature.
type ed25519phVerifier struct{}

// VerifySignature verifies the upgrade's signature with Ed25519ph.
func (v ed25519phVerifier) VerifySignature(checksum []byte, signature []byte, _ crypto.Hash, publicKey crypto.PublicKey) error {
	opts := &ed25519.Options{Hash: crypto.SHA512, Context: Product}
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
