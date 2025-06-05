package api

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

	"go.acuvity.ai/elemental"
)

// ValidateURL validates the given value is a correct url.
func ValidateURL(attribute string, u string) error {

	if u == "" {
		return nil
	}

	uu, err := url.Parse(u)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("invalid url: %s", err))
	}

	switch uu.Scheme {
	case "http", "https":
	case "":
		return makeErr(attribute, "invalid url: missing scheme")
	default:
		return makeErr(attribute, "invalid url: invalid scheme")
	}

	return nil
}

// ValidateNonEmptyList validates that a list is not empty.
func ValidateNonEmptyList[T any](attribute string, list []T) error {

	if len(list) == 0 {
		return makeErr(attribute, fmt.Sprintf("'%s' cannot be empty", attribute))
	}

	return nil
}

// ValidatePrincipal validates the principal object.
func ValidatePrincipal(principal *Principal) error {

	switch principal.Type {
	case PrincipalTypeApp:
		if principal.App == nil {
			return makeErr("app", "'App' must have its information defined.")
		}
	case PrincipalTypeUser:
		if principal.User == nil {
			return makeErr("user", "'User' must have its information defined.")
		}
	}

	return nil
}

func makeErr(attribute string, message string) elemental.Error {

	err := elemental.NewError(
		"Validation Error",
		message,
		"a3s",
		http.StatusUnprocessableEntity,
	)

	if attribute != "" {
		err.Data = map[string]any{"attribute": attribute}
	}

	return err
}

// ValidateSpanID validates the span ID. It must be a hex encoded string and must be 8 bytes long.
func ValidateSpanID(attribute, spanID string) error {

	if spanID == "" {
		return nil
	}

	b, err := hex.DecodeString(spanID)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("'%s' must be a valid hex string: %s", attribute, err))
	}
	if len(b) != 8 {
		return makeErr(attribute, fmt.Sprintf("'%s' must be exactly 8 bytes long.", attribute))
	}

	return nil
}

// ValidateTraceID validates the trace ID. It must be a hex encoded string and must be 16 bytes long.
func ValidateTraceID(attribute, traceID string) error {

	if traceID == "" {
		return nil
	}

	b, err := hex.DecodeString(traceID)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("'%s' must be a valid hex string: %s", attribute, err))
	}
	if len(b) != 16 {
		return makeErr(attribute, fmt.Sprintf("'%s' must be exactly 16 bytes long.", attribute))
	}

	return nil
}
