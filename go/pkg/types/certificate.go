// go/pkg/types/certificate.go
package types

import "time"

// Certificate represents a TLS certificate
type Certificate struct {
	BaseType
	Host      string    `json:"host"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SANs      []string  `json:"sans,omitempty"`
}

func (c *Certificate) Type() string { return "certificate" }

func (c *Certificate) ToMap() map[string]any {
	m := c.BaseType.ToMap()
	m["_type"] = "certificate"
	m["host"] = c.Host
	m["issuer"] = c.Issuer
	m["subject"] = c.Subject
	m["not_before"] = c.NotBefore
	m["not_after"] = c.NotAfter
	m["sans"] = c.SANs
	return m
}
