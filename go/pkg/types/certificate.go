// go/pkg/types/certificate.go
package types

import (
	"fmt"
	"time"

	"github.com/freelabz/secator/pkg/console"
)

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

// String returns a formatted console representation
// Format: 🔐 host [subject] [issuer] [expiry]
func (c *Certificate) String() string {
	str := fmt.Sprintf("🔐 %s", console.White(c.Host))

	if c.Subject != "" {
		str += fmt.Sprintf(" [%s]", console.Green(c.Subject))
	}

	if c.Issuer != "" {
		str += fmt.Sprintf(" [%s]", console.Magenta(c.Issuer))
	}

	// Expiry with color (red if expired, yellow if expiring soon)
	if !c.NotAfter.IsZero() {
		now := time.Now()
		expiry := c.NotAfter.Format("2006-01-02")
		if c.NotAfter.Before(now) {
			str += fmt.Sprintf(" [%s]", console.BoldRed("expired: "+expiry))
		} else if c.NotAfter.Before(now.AddDate(0, 1, 0)) {
			str += fmt.Sprintf(" [%s]", console.Yellow("expires: "+expiry))
		} else {
			str += fmt.Sprintf(" [%s]", console.Dim("expires: "+expiry))
		}
	}

	return str
}
