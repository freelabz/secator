// go/pkg/types/subdomain.go
package types

// Subdomain represents a discovered subdomain
type Subdomain struct {
	BaseType
	Host        string   `json:"host"`
	Domain      string   `json:"domain,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	Resolved    bool     `json:"resolved,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
}

func (s *Subdomain) Type() string { return "subdomain" }

func (s *Subdomain) ToMap() map[string]any {
	m := s.BaseType.ToMap()
	m["_type"] = "subdomain"
	m["host"] = s.Host
	m["domain"] = s.Domain
	m["sources"] = s.Sources
	m["resolved"] = s.Resolved
	m["ip_addresses"] = s.IPAddresses
	return m
}
