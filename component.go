package keygen

import (
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

type component struct {
	ID          string                 `json:"-"`
	Type        string                 `json:"-"`
	Fingerprint string                 `json:"fingerprint"`
	Name        string                 `json:"name"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	MachineID   string                 `json:"-"`
}

// GetID implements the jsonapi.MarshalResourceIdentifier interface.
func (c component) GetID() string {
	return c.ID
}

// GetType implements the jsonapi.MarshalResourceIdentifier interface.
func (c component) GetType() string {
	return "components"
}

// GetData implements the jsonapi.MarshalData interface.
func (c component) GetData() interface{} {
	return c
}

// GetRelationships implements jsonapi.MarshalRelationships interface.
func (c component) GetRelationships() map[string]interface{} {
	relationships := make(map[string]interface{})

	if c.MachineID != "" {
		relationships["machine"] = jsonapi.ResourceObjectIdentifier{
			Type: "machines",
			ID:   c.MachineID,
		}
	}

	if len(relationships) == 0 {
		return nil
	}

	return relationships
}

// Component represents a Keygen component object.
type Component struct {
	ID          string                 `json:"-"`
	Type        string                 `json:"-"`
	Fingerprint string                 `json:"fingerprint"`
	Name        string                 `json:"name"`
	Created     time.Time              `json:"created"`
	Updated     time.Time              `json:"updated"`
	Metadata    map[string]interface{} `json:"metadata"`
	MachineID   string                 `json:"-"`
}

// GetID implements the jsonapi.MarshalResourceIdentifier interface.
func (c Component) GetID() string {
	return c.ID
}

// GetType implements the jsonapi.MarshalResourceIdentifier interface.
func (c Component) GetType() string {
	return "components"
}

// GetData implements the jsonapi.MarshalData interface.
func (c Component) GetData() interface{} {
	// Transform public component to private component to only send a subset of attrs
	return component{
		Fingerprint: c.Fingerprint,
		Name:        c.Name,
		Metadata:    c.Metadata,
		MachineID:   c.MachineID,
	}
}

func (c Component) UseExperimentalEmbeddedRelationshipData() bool {
	return true
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (c *Component) SetID(id string) error {
	c.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (c *Component) SetType(t string) error {
	c.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (c *Component) SetData(to func(target interface{}) error) error {
	return to(c)
}

// Components represents an array of component objects.
type Components []Component

// SetData implements the jsonapi.UnmarshalData interface.
func (c *Components) SetData(to func(target interface{}) error) error {
	return to(c)
}
