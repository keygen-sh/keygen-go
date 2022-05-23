package keygen

import (
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

// Artifact represents a Keygen artifact object.
type Artifact struct {
	ID        string    `json:"-"`
	Type      string    `json:"-"`
	Filename  string    `json:"filename"`
	Filetype  string    `json:"filetype"`
	Filesize  int64     `json:"filesize"`
	Platform  string    `json:"platform"`
	Arch      string    `json:"arch"`
	Signature string    `json:"signature"`
	Checksum  string    `json:"checksum"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	ReleaseId string    `json:"-"`
	URL       string    `json:"-"`
}

// Implement jsonapi.UnmarshalData interface
func (a *Artifact) SetID(id string) error {
	a.ID = id
	return nil
}

func (a *Artifact) SetType(t string) error {
	a.Type = t
	return nil
}

func (a *Artifact) SetData(to func(target interface{}) error) error {
	return to(a)
}

func (a *Artifact) SetRelationships(relationships map[string]interface{}) error {
	if relationship, ok := relationships["release"]; ok {
		a.ReleaseId = relationship.(*jsonapi.ResourceObjectIdentifier).ID
	}

	return nil
}
