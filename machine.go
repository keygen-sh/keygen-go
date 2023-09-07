package keygen

import (
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

type HeartbeatStatusCode string

const (
	HeartbeatStatusCodeNotStarted  HeartbeatStatusCode = "NOT_STARTED"
	HeartbeatStatusCodeAlive       HeartbeatStatusCode = "ALIVE"
	HeartbeatStatusCodeDead        HeartbeatStatusCode = "DEAD"
	HeartbeatStatusCodeResurrected HeartbeatStatusCode = "RESURRECTED"
)

type machine struct {
	ID          string `json:"-"`
	Type        string `json:"-"`
	Fingerprint string `json:"fingerprint"`
	Hostname    string `json:"hostname"`
	Platform    string `json:"platform"`
	Cores       int    `json:"cores"`
	LicenseID   string `json:"-"`
}

// GetID implements the jsonapi.MarshalResourceIdentifier interface.
func (m machine) GetID() string {
	return m.ID
}

// GetType implements the jsonapi.MarshalResourceIdentifier interface.
func (m machine) GetType() string {
	return "machines"
}

// GetData implements the jsonapi.MarshalData interface.
func (m machine) GetData() interface{} {
	return m
}

// GetRelationships implements jsonapi.MarshalRelationships interface.
func (m machine) GetRelationships() map[string]interface{} {
	relationships := make(map[string]interface{})

	relationships["license"] = jsonapi.ResourceObjectIdentifier{
		Type: "licenses",
		ID:   m.LicenseID,
	}

	return relationships
}

// Machine represents a Keygen machine object.
type Machine struct {
	ID                string                 `json:"-"`
	Type              string                 `json:"-"`
	Name              string                 `json:"name"`
	Fingerprint       string                 `json:"fingerprint"`
	Hostname          string                 `json:"hostname"`
	Platform          string                 `json:"platform"`
	Cores             int                    `json:"cores"`
	RequireHeartbeat  bool                   `json:"requireHeartbeat"`
	HeartbeatStatus   HeartbeatStatusCode    `json:"heartbeatStatus"`
	HeartbeatDuration int                    `json:"heartbeatDuration"`
	Created           time.Time              `json:"created"`
	Updated           time.Time              `json:"updated"`
	Metadata          map[string]interface{} `json:"metadata"`
	LicenseID         string                 `json:"-"`
}

// GetID implements the jsonapi.MarshalResourceIdentifier interface.
func (m Machine) GetID() string {
	return m.ID
}

// GetType implements the jsonapi.MarshalResourceIdentifier interface.
func (m Machine) GetType() string {
	return "machines"
}

// GetData implements the jsonapi.MarshalData interface.
func (m Machine) GetData() interface{} {
	// Transform public machine to private machine to only send a subset of attrs
	return machine{
		Fingerprint: m.Fingerprint,
		Hostname:    m.Hostname,
		Platform:    m.Platform,
		Cores:       m.Cores,
		LicenseID:   m.LicenseID,
	}
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (m *Machine) SetID(id string) error {
	m.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (m *Machine) SetType(t string) error {
	m.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (m *Machine) SetData(to func(target interface{}) error) error {
	return to(m)
}

// Machines represents an array of machine objects.
type Machines []Machine

// SetData implements the jsonapi.UnmarshalData interface.
func (m *Machines) SetData(to func(target interface{}) error) error {
	return to(m)
}

// Deactivate performs a machine deactivation for the current Machine. An error
// will be returned if the machine deactivation fails.
func (m *Machine) Deactivate() error {
	client := NewClient()

	if _, err := client.Delete("machines/"+m.ID, nil, nil); err != nil {
		return err
	}

	return nil
}

// Monitor performs, on a loop, a machine hearbeat ping for the current Machine. An
// error channel will be returned, where any ping errors will be emitted. Pings are
// sent according to the machine's required heartbeat window, minus 30 seconds to
// account for any network lag. Panics if a heartbeat ping fails after first ping.
func (m *Machine) Monitor() error {
	if err := m.ping(); err != nil {
		return err
	}

	go func() {
		t := (time.Duration(m.HeartbeatDuration) * time.Second) - (30 * time.Second)

		for range time.Tick(t) {
			if err := m.ping(); err != nil {
				panic(err)
			}
		}
	}()

	return nil
}

// Checkout generates an encrypted machine file. Returns a MachineFile.
func (m *Machine) Checkout(options ...CheckoutOption) (*MachineFile, error) {
	client := NewClient()
	license := &License{}
	lic := &MachineFile{}

	opts := CheckoutOptions{Encrypt: true, Include: "license,license.entitlements"}
	for _, opt := range options {
		err := opt(&opts)
		if err != nil {
			return nil, err
		}
	}

	if _, err := client.Get("me", nil, license); err != nil {
		return nil, err
	}

	if _, err := client.Post("machines/"+m.ID+"/actions/check-out", opts, lic); err != nil {
		return nil, err
	}

	return lic, nil
}

// Spawn creates a new process for a machine, identified by the provided pid. If
// successful, the new Process will be returned. When unsuccessful, as error
// will be returned, e.g. ErrProcessLimitExceeded. Automatically starts a loop
// that sends heartbeat pings according to the process's Interval. Panics if a
// heartbeat ping fails after first ping.
func (m *Machine) Spawn(pid string) (*Process, error) {
	client := NewClient()
	params := &Process{
		Pid:       pid,
		MachineID: m.ID,
	}

	process := &Process{}
	if _, err := client.Post("processes", params, process); err != nil {
		return nil, err
	}

	if err := process.monitor(); err != nil {
		return process, err
	}

	return process, nil
}

// Processes lists up to 100 processes for the machine.
func (m *Machine) Processes() (Processes, error) {
	client := NewClient()
	processes := Processes{}

	if _, err := client.Get("machines/"+m.ID+"/processes", querystring{Limit: 100}, &processes); err != nil {
		return nil, err
	}

	return processes, nil
}

func (m *Machine) ping() error {
	client := NewClient()

	if _, err := client.Post("machines/"+m.ID+"/actions/ping", nil, m); err != nil {
		return err
	}

	return nil
}
