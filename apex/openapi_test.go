package api

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"testing"
)

func TestOpenAPI(t *testing.T) {

	test := func(name string, f func(bool) ([]byte, string, error), arg bool) func(*testing.T) {
		return func(t *testing.T) {
			_, etag, err := f(arg)
			if err != nil {
				t.Errorf("%s(%v) failed: %s", name, arg, err)
			}
			if etag == "" {
				t.Errorf("%s(%v) failed: etag is empty", name, arg)
			}
		}
	}
	t.Run("JSON without extensions", test("OpenAPIJSON", OpenAPIJSON, false))
	t.Run("JSON with extensions", test("OpenAPIJSON", OpenAPIJSON, true))

	t.Run("YAML without extensions", test("OpenAPIYAML", OpenAPIYAML, false))
	t.Run("YAML with extensions", test("OpenAPIYAML", OpenAPIYAML, true))

}

func Test_filterExtensions(t *testing.T) {

	d1Bytes := `
{
  "tags": [
    {
      "description": "This tag is for group 'apex'",
      "name": "apex"
    },
    {
      "description": "This tag is for group 'core'",
      "name": "core"
    }
  ],
  "x-speakeasy-retries": {
    "backoff": {
      "exponent": 1.5,
      "initialInterval": 1000,
      "maxElapsedTime": 300000,
      "maxInterval": 60000
    },
    "retryConnectionErrors": true,
    "statusCodes": [
      408,
      423,
      429,
      502,
      503,
      504
    ],
    "strategy": "backoff"
  },
  "x-speakeasy-timeout": 60000
}`

	var d1 map[string]any
	if err := json.Unmarshal([]byte(d1Bytes), &d1); err != nil {
		panic(err)
	}

	d2Bytes := `
{
  "paths": {
    "/_acuvity/analyzers": {
      "get": {
        "description": "List of all available analyzers.",
        "operationId": "get-all-Analyzers",
        "tags": [
          "apex"
        ],
        "x-speakeasy-name-override": "listAnalyzers",
        "x-speakeasy-usage-example": {
          "description": "Now you can list all available analyzers that can be used in the Scan API.",
          "position": 2,
          "title": "List all available analyzers"
        }
      }
    },
    "/_acuvity/scan": {
      "post": {
        "description": "Processes the scan request.",
        "operationId": "create-ScanRequest-as-ScanResponse",
        "tags": [
          "apex"
        ],
        "x-speakeasy-name-override": "scanRequest",
        "x-speakeasy-usage-example": {
          "description": "Now you can submit a scan request using the Scan API.",
          "position": 1,
          "title": "Process a scan request"
        }
      }
    }
  }
}`

	var d2 map[string]any
	if err := json.Unmarshal([]byte(d2Bytes), &d2); err != nil {
		panic(err)
	}

	type args struct {
		data any
	}
	tests := []struct {
		name string
		args args
		want any
	}{
		{
			name: "one",
			args: args{data: d1},
			want: map[string]any{
				"tags": []any{
					map[string]any{
						"description": "This tag is for group 'apex'",
						"name":        "apex",
					},
					map[string]any{
						"description": "This tag is for group 'core'",
						"name":        "core",
					},
				},
			},
		},
		{
			name: "two",
			args: args{data: d2},
			want: map[string]any{
				"paths": map[string]any{
					"/_acuvity/analyzers": map[string]any{
						"get": map[string]any{
							"description": "List of all available analyzers.",
							"operationId": "get-all-Analyzers",
							"tags":        []any{"apex"},
						},
					},
					"/_acuvity/scan": map[string]any{
						"post": map[string]any{
							"description": "Processes the scan request.",
							"operationId": "create-ScanRequest-as-ScanResponse",
							"tags":        []any{"apex"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterExtensions(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterExtensions() = %v, want %v", got, tt.want)
			}
		})
	}
}
