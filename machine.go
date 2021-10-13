package keygen

import (
	"time"

	"github.com/pieoneers/jsonapi-go"
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

// Implement jsonapi.MarshalData interface
func (m machine) GetID() string {
	return m.ID
}

func (m machine) GetType() string {
	return "machines"
}

func (m machine) GetData() interface{} {
	return m
}

// Implement jsonapi.MarshalRelationships interface
func (m machine) GetRelationships() map[string]interface{} {
	relationships := make(map[string]interface{})

	relationships["license"] = jsonapi.ResourceObjectIdentifier{
		Type: "licenses",
		ID:   m.LicenseID,
	}

	return relationships
}

// Machine represents an Keygen machine object.
type Machine struct {
	ID                string                 `json:"-"`
	Type              string                 `json:"-"`
	Name              string                 `json:"name"`
	Fingerprint       string                 `json:"fingerprint"`
	Hostname          string                 `json:"hostname"`
	Platform          string                 `json:"platform"`
	Cores             int                    `json:"cores"`
	HeartbeatStatus   string                 `json:"heartbeatStatus"`
	HeartbeatDuration int                    `json:"heartbeatDuration"`
	Created           time.Time              `json:"created"`
	Updated           time.Time              `json:"updated"`
	Metadata          map[string]interface{} `json:"metadata"`
	LicenseID         string                 `json:"-"`
}

// Implement jsonapi.MarshalData interface
func (m Machine) GetID() string {
	return m.ID
}

func (m Machine) GetType() string {
	return "machines"
}

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

// Implement jsonapi.UnmarshalData interface
func (m *Machine) SetID(id string) error {
	m.ID = id
	return nil
}

func (m *Machine) SetType(t string) error {
	m.Type = t
	return nil
}

func (m *Machine) SetData(to func(target interface{}) error) error {
	return to(m)
}

// Machines represents an array of machine objects.
type Machines []Machine

// Implement jsonapi.UnmarshalData interface
func (m *Machines) SetData(to func(target interface{}) error) error {
	return to(m)
}

// Deactivate performs a machine deactivation for the current Machine. An error
// will be returned if the machine deactivation fails.
func (m *Machine) Deactivate() error {
	client := &Client{Account: Account, Token: Token}

	if _, err := client.Delete("machines/"+m.ID, nil, nil); err != nil {
		return err
	}

	return nil
}

// Monitor performs, on a loop, a machine hearbeat ping for the current Machine. An
// error channel will be returned, where any ping errors will be emitted. Pings are
// sent according to the machine's required heartbeat window.
func (m *Machine) Monitor() chan error {
	client := &Client{Account: Account, Token: Token}
	errs := make(chan error)
	t := time.Duration(m.HeartbeatDuration) * time.Second / 2

	go func() {
		m.ping(client, errs)

		for range time.Tick(t) {
			m.ping(client, errs)
		}
	}()

	return errs
}

func (m *Machine) ping(client *Client, errs chan error) {
	if _, err := client.Post("machines/"+m.ID+"/actions/ping-heartbeat", nil, &m); err != nil {
		errs <- err
	}
}
