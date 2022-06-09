package keygen

import (
	"time"

	"github.com/keygen-sh/jsonapi-go"
)

type ProcessStatusCode string

const (
	ProcessStatusCodeAlive ProcessStatusCode = "ALIVE"
	ProcessStatusCodeDead  ProcessStatusCode = "DEAD"
)

type process struct {
	ID        string `json:"-"`
	Type      string `json:"-"`
	Pid       string `json:"pid"`
	MachineID string `json:"-"`
}

// GetID implements the jsonapi.MarshalResourceIdentifier interface.
func (p process) GetID() string {
	return p.ID
}

// GetType implements the jsonapi.MarshalResourceIdentifier interface.
func (p process) GetType() string {
	return "processes"
}

// GetData implements the jsonapi.MarshalData interface.
func (p process) GetData() interface{} {
	return p
}

// GetRelationships implements jsonapi.MarshalRelationships interface.
func (p process) GetRelationships() map[string]interface{} {
	relationships := make(map[string]interface{})

	relationships["machine"] = jsonapi.ResourceObjectIdentifier{
		Type: "machines",
		ID:   p.MachineID,
	}

	return relationships
}

// Process represents a Keygen process object.
type Process struct {
	ID        string                 `json:"-"`
	Type      string                 `json:"-"`
	Pid       string                 `json:"pid"`
	Status    ProcessStatusCode      `json:"status"`
	Interval  int                    `json:"interval"`
	Created   time.Time              `json:"created"`
	Updated   time.Time              `json:"updated"`
	Metadata  map[string]interface{} `json:"metadata"`
	MachineID string                 `json:"-"`
}

// GetID implements the jsonapi.MarshalResourceIdentifier interface.
func (p Process) GetID() string {
	return p.ID
}

// GetType implements the jsonapi.MarshalResourceIdentifier interface.
func (p Process) GetType() string {
	return "processes"
}

// GetData implements the jsonapi.MarshalData interface.
func (p Process) GetData() interface{} {
	// Transform public process to private process to only send a subset of attrs
	return process{
		Pid:       p.Pid,
		MachineID: p.MachineID,
	}
}

// SetID implements the jsonapi.UnmarshalResourceIdentifier interface.
func (p *Process) SetID(id string) error {
	p.ID = id
	return nil
}

// SetType implements the jsonapi.UnmarshalResourceIdentifier interface.
func (p *Process) SetType(t string) error {
	p.Type = t
	return nil
}

// SetData implements the jsonapi.UnmarshalData interface.
func (p *Process) SetData(to func(target interface{}) error) error {
	return to(p)
}

// Processes represents an array of process objects.
type Processes []Process

// SetData implements the jsonapi.UnmarshalData interface.
func (p *Processes) SetData(to func(target interface{}) error) error {
	return to(p)
}

// Kill deletes the current Process. An error will be returned if the process
// deletion fails.
func (p *Process) Kill() error {
	client := NewClient()

	if _, err := client.Delete("processes/"+p.ID, nil, nil); err != nil {
		return err
	}

	return nil
}

func (p *Process) monitor() error {
	if err := p.ping(); err != nil {
		return err
	}

	go func() {
		t := (time.Duration(p.Interval) * time.Second) - (30 * time.Second)

		for range time.Tick(t) {
			if err := p.ping(); err != nil {
				panic(err)
			}
		}
	}()

	return nil
}

func (p *Process) ping() error {
	client := NewClient()

	if _, err := client.Post("processes/"+p.ID+"/actions/ping", nil, p); err != nil {
		return err
	}

	return nil
}
