// go/pkg/types/url_test.go
package types

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURL_ImplementsOutputType(t *testing.T) {
	var _ OutputType = &URL{}
}

func TestURL_Type(t *testing.T) {
	u := &URL{}
	assert.Equal(t, "url", u.Type())
}

func TestURL_ToMap(t *testing.T) {
	u := &URL{
		URL:          "https://example.com",
		Host:         "example.com",
		Port:         443,
		Scheme:       "https",
		StatusCode:   200,
		ContentType:  "text/html",
		Technologies: []string{"nginx"},
	}
	u.SetSource("httpx")

	m := u.ToMap()
	assert.Equal(t, "url", m["_type"])
	assert.Equal(t, "https://example.com", m["url"])
	assert.Equal(t, 200, m["status_code"])
	assert.Equal(t, []string{"nginx"}, m["technologies"])
}

func TestURL_ParseFromHTTPX(t *testing.T) {
	data, err := os.ReadFile("../../testdata/httpx_output.json")
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	url, err := URLFromMap(raw)
	require.NoError(t, err)

	assert.Equal(t, "https://media.example.synology.me:443", url.URL)
	assert.Equal(t, "82.61.151.800", url.Host)
	assert.Equal(t, 443, url.Port)
	assert.Equal(t, "https", url.Scheme)
	assert.Equal(t, 200, url.StatusCode)
	assert.Equal(t, "text/html", url.ContentType)
	assert.Contains(t, url.Technologies, "Nginx")
}
