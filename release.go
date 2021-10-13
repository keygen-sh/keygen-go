package keygen

import (
	"errors"
	"net/http"
	"time"

	"github.com/inconshreveable/go-update"
)

var (
	ErrReleaseLocationMissing = errors.New("release has no download URL")
)

// Release represents an Keygen release object.
type Release struct {
	ID       string    `json:"-"`
	Type     string    `json:"-"`
	Version  string    `json:"version"`
	Filename string    `json:"filename"`
	Filetype string    `json:"filetype"`
	Filesize string    `json:"filesize"`
	Platform string    `json:"platform"`
	Channel  string    `json:"channel"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Location string    `json:"-"`
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

	// TODO(ezekg) Add Ed25519 signature verification
	// TODO(ezekg) Add SHA256 checksum verification
	err = update.Apply(res.Body, update.Options{})
	if err != nil {
		return err
	}

	return nil
}
