package keygen

import "time"

// Entitlement represents a Keygen entitlement object.
type Entitlement struct {
	ID       string                 `json:"-"`
	Type     string                 `json:"-"`
	Code     string                 `json:"code"`
	Created  time.Time              `json:"created"`
	Updated  time.Time              `json:"updated"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Implement jsonapi.UnmarshalData interface
func (e *Entitlement) SetID(id string) error {
	e.ID = id
	return nil
}

func (e *Entitlement) SetType(t string) error {
	e.Type = t
	return nil
}

func (e *Entitlement) SetData(to func(target interface{}) error) error {
	return to(e)
}

// Entitlements represents an array of entitlement objects.
type Entitlements []Entitlement

// Implement jsonapi.UnmarshalData interface
func (e *Entitlements) SetData(to func(target interface{}) error) error {
	return to(e)
}
