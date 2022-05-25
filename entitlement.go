package keygen

import "time"

type EntitlementCode string

// Entitlement represents a Keygen entitlement object.
type Entitlement struct {
	ID       string                 `json:"-"`
	Type     string                 `json:"-"`
	Code     EntitlementCode        `json:"code"`
	Created  time.Time              `json:"created"`
	Updated  time.Time              `json:"updated"`
	Metadata map[string]interface{} `json:"metadata"`
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (e *Entitlement) SetID(id string) error {
	e.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (e *Entitlement) SetType(t string) error {
	e.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (e *Entitlement) SetData(to func(target interface{}) error) error {
	return to(e)
}

// Entitlements represents an array of entitlement objects.
type Entitlements []Entitlement

// SetData implements the jsonapi.UnmarshalData interface.
func (e *Entitlements) SetData(to func(target interface{}) error) error {
	return to(e)
}
