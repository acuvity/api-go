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
		if principal.User != nil || principal.External != nil {
			return makeErr("app", "'App' must not have 'User' or 'External' defined.")
		}
	case PrincipalTypeUser:
		if principal.User == nil {
			return makeErr("user", "'User' must have its information defined.")
		}
		if principal.App != nil || principal.External != nil {
			return makeErr("user", "'User' must not have 'App' or 'External' defined.")
		}
	case PrincipalTypeExternal:
		if principal.External == nil {
			return makeErr("external", "'External' must have its information defined.")
		}
		if principal.User != nil || principal.App != nil {
			return makeErr("external", "'External' must not have 'User' or 'App' defined.")
		}
	}

	return nil
}

// ValidateRequestApp validates the request app.
func ValidateRequestApp(o *RequestApp) error {

	if o.Direction == RequestAppDirectionIngress {
		if o.Port <= 0 {
			return makeErr("port", "'port' must be set and > 0 when direction is Ingress")
		}
	}

	return nil
}

// ValidateScanRequest validates the scan request.
func ValidateScanRequest(o *ScanRequest) error {

	// Existing validations.
	if len(o.Redactions) > 0 && o.ContentPolicy != "" {
		return makeErr("redactions", "if redactions are set, you cannot use contentPolicy and vice versa")
	}
	if len(o.Keywords) > 0 && o.AccessPolicy != "" {
		return makeErr("keywords", "if keywords are set, you cannot use accessPolicy and vice versa")
	}
	if len(o.Analyzers) > 0 && o.AccessPolicy != "" {
		return makeErr("analyzers", "if analyzers are set, you cannot use accessPolicy and vice versa")
	}

	// When app/destination/provider are optionally provided, same rules as police apply.
	hasDestApp := o.Destination != nil && o.Destination.App != "" && o.Destination.Component != ""
	hasProvider := o.Provider != ""
	isIngress := o.App != nil && o.App.Direction == RequestAppDirectionIngress

	if hasDestApp && hasProvider {
		return makeErr("provider", "'provider' must not be set when destination app and component are set")
	}

	if isIngress {
		if hasProvider {
			return makeErr("provider", "'provider' must not be set when direction is Ingress")
		}
		if hasDestApp {
			return makeErr("destination", "'destination' must not be set when direction is Ingress; the app field is the destination")
		}
	}

	return nil
}

// ValidatePoliceRequest validates the police request.
func ValidatePoliceRequest(o *PoliceRequest) error {

	hasDestApp := o.Destination != nil && o.Destination.App != "" && o.Destination.Component != ""
	hasProvider := o.Provider != ""
	isIngress := o.App != nil && o.App.Direction == RequestAppDirectionIngress

	if hasDestApp && hasProvider {
		return makeErr("provider", "'provider' must not be set when destination app and component are set")
	}

	if isIngress {
		if hasProvider {
			return makeErr("provider", "'provider' must not be set when direction is Ingress")
		}
		if hasDestApp {
			return makeErr("destination", "'destination' must not be set when direction is Ingress; the app field is the destination")
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
