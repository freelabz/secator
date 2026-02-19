// go/pkg/types/subdomain.go
package types

import (
	"fmt"
	"strings"

	"github.com/freelabz/secator/pkg/console"
)

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

// String returns a formatted console representation
// Format: 🏰 subdomain.example.com [source1, source2]
func (s *Subdomain) String() string {
	str := fmt.Sprintf("🏰 %s", console.White(s.Host))

	// Sources
	if len(s.Sources) > 0 {
		colored := make([]string, len(s.Sources))
		for i, src := range s.Sources {
			colored[i] = console.Magenta(src)
		}
		str += fmt.Sprintf(" [%s]", strings.Join(colored, ", "))
	}

	// Dim if not resolved
	if !s.Resolved {
		str = console.Dim(str)
	}

	return str
}
