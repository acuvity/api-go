package api

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"

	"github.com/ghodss/yaml"
)

//go:embed openapi3/toplevel
var openapiBytes []byte

var openapiBytesEtag = sync.OnceValue(func() string {
	return etagFromBytes(openapiBytes)
})

var openapiFilteredBytes = sync.OnceValues(func() ([]byte, error) {
	var obj map[string]any
	if err := json.Unmarshal(openapiBytes, &obj); err != nil {
		return nil, err
	}
	filteredObj := filterExtensions(obj)
	retBytes, err := json.Marshal(filteredObj)
	if err != nil {
		return nil, err
	}
	return retBytes, nil
})

var openapiFilteredBytesEtag = sync.OnceValue(func() string {
	b, err := openapiFilteredBytes()
	if err != nil {
		return ""
	}
	return etagFromBytes(b)
})

var openapiYAMLBytes = sync.OnceValues(func() ([]byte, error) {
	var obj map[string]any
	if err := json.Unmarshal(openapiBytes, &obj); err != nil {
		return nil, err
	}
	retBytes, err := yaml.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return retBytes, nil
})

var openapiYAMLBytesEtag = sync.OnceValue(func() string {
	b, err := openapiYAMLBytes()
	if err != nil {
		return ""
	}
	return etagFromBytes(b)
})

var openapiYAMLFilteredBytes = sync.OnceValues(func() ([]byte, error) {
	var obj map[string]any
	if err := json.Unmarshal(openapiBytes, &obj); err != nil {
		return nil, err
	}
	filteredObj := filterExtensions(obj)
	retBytes, err := yaml.Marshal(filteredObj)
	if err != nil {
		return nil, err
	}
	return retBytes, nil
})

var openapiYAMLFilteredBytesEtag = sync.OnceValue(func() string {
	b, err := openapiYAMLFilteredBytes()
	if err != nil {
		return ""
	}
	return etagFromBytes(b)
})

// OpenAPIJSON returns the OpenAPI spec in JSON format
func OpenAPIJSON(includeExtensions bool) ([]byte, string, error) {
	if includeExtensions {
		return openapiBytes, openapiBytesEtag(), nil
	}
	b, err := openapiFilteredBytes()
	if err != nil {
		return nil, "", err
	}
	return b, openapiFilteredBytesEtag(), nil
}

// OpenAPIYAML returns the OpenAPI spec in YAML format
func OpenAPIYAML(includeExtensions bool) ([]byte, string, error) {
	if includeExtensions {
		b, err := openapiYAMLBytes()
		if err != nil {
			return nil, "", err
		}
		return b, openapiYAMLBytesEtag(), nil
	}
	b, err := openapiYAMLFilteredBytes()
	if err != nil {
		return nil, "", err
	}
	return b, openapiYAMLFilteredBytesEtag(), nil
}

// etagFromBytes generates an ETag from a byte slice
func etagFromBytes(b []byte) string {
	// Generate ETag using SHA-256 hash
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// filterExtensions recursively filters fields starting with "x-"
func filterExtensions(data any) any {
	switch v := data.(type) {
	case map[string]any:
		filtered := make(map[string]any, len(v))
		for key, value := range v {
			if !strings.HasPrefix(key, "x-") {
				filtered[key] = filterExtensions(value)
			}
		}
		return filtered

	case []any:
		for i, item := range v {
			v[i] = filterExtensions(item)
		}
		return v

	default:
		return v
	}
}
