// go/pkg/types/url.go
package types

import (
	"fmt"
	"strconv"
)

// URL represents an HTTP URL finding
type URL struct {
	BaseType
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
	Title         string   `json:"title,omitempty"`
	Webserver     string   `json:"webserver,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	FinalURL      string   `json:"final_url,omitempty"`
}

func (u *URL) Type() string {
	return "url"
}

func (u *URL) ToMap() map[string]any {
	m := u.BaseType.ToMap()
	m["_type"] = "url"
	m["url"] = u.URL
	m["host"] = u.Host
	m["port"] = u.Port
	m["scheme"] = u.Scheme
	m["status_code"] = u.StatusCode
	m["content_type"] = u.ContentType
	m["content_length"] = u.ContentLength
	m["title"] = u.Title
	m["webserver"] = u.Webserver
	m["technologies"] = u.Technologies
	m["final_url"] = u.FinalURL
	return m
}

// URLFromMap creates a URL from a raw map (e.g., from httpx JSON)
func URLFromMap(raw map[string]any) (*URL, error) {
	u := &URL{}

	if v, ok := raw["url"].(string); ok {
		u.URL = v
	}
	if v, ok := raw["host"].(string); ok {
		u.Host = v
	}
	if v, ok := raw["port"].(string); ok {
		u.Port, _ = strconv.Atoi(v)
	} else if v, ok := raw["port"].(float64); ok {
		u.Port = int(v)
	}
	if v, ok := raw["scheme"].(string); ok {
		u.Scheme = v
	}
	if v, ok := raw["status_code"].(float64); ok {
		u.StatusCode = int(v)
	}
	if v, ok := raw["content_type"].(string); ok {
		u.ContentType = v
	}
	if v, ok := raw["content_length"].(float64); ok {
		u.ContentLength = int(v)
	}
	if v, ok := raw["title"].(string); ok {
		u.Title = v
	}
	if v, ok := raw["webserver"].(string); ok {
		u.Webserver = v
	}
	if v, ok := raw["tech"].([]any); ok {
		for _, t := range v {
			if s, ok := t.(string); ok {
				u.Technologies = append(u.Technologies, s)
			}
		}
	}
	if v, ok := raw["final_url"].(string); ok {
		u.FinalURL = v
	}

	// Extract port from URL if not set
	if u.Port == 0 && u.Scheme == "https" {
		u.Port = 443
	} else if u.Port == 0 && u.Scheme == "http" {
		u.Port = 80
	}

	if u.URL == "" {
		return nil, fmt.Errorf("url field is required")
	}

	return u, nil
}
