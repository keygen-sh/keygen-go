package keygen

import (
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

// Artifact represents a Keygen artifact object.
type Artifact struct {
	ID        string    `json:"-"`
	Type      string    `json:"-"`
	Key       string    `json:"key"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	ReleaseId string    `json:"-"`
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

func (a *Artifact) release() (*Release, error) {
	client := &Client{Account: Account, Token: Token}
	release := &Release{}

	if _, err := client.Get("releases/"+a.ReleaseId, nil, release); err != nil {
		return nil, err
	}

	return release, nil
}
