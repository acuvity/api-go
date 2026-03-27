package api

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed jsonschema
var jsonschemaFS embed.FS

// JSONSchema returns the JSON schema bytes for the given schema name (e.g. "import.json").
func JSONSchema(name string) ([]byte, error) {
	sub, err := fs.Sub(jsonschemaFS, "jsonschema")
	if err != nil {
		return nil, fmt.Errorf("unable to open jsonschema fs: %w", err)
	}
	b, err := fs.ReadFile(sub, name)
	if err != nil {
		return nil, fmt.Errorf("unknown schema %q", name)
	}
	return b, nil
}
