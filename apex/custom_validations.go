package api

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

	"go.acuvity.ai/elemental"
)

// ValidateURL validates the given value is a correct url with any scheme.
func ValidateURL(attribute string, u string) error {

	if u == "" {
		return nil
	}

	uu, err := url.Parse(u)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("invalid url: %s", err))
	}

	if uu.Scheme == "" {
		return makeErr(attribute, "invalid url: missing scheme")
	}

	if uu.Hostname() == "" {
		return makeErr(attribute, "invalid url: missing hostname")
	}

	return nil
}

// ValidateWebSchemeURL validates that the given url uses a web scheme (http, https, ws, wss).
// Intended to be paired with $url: $url validates structure, $webscheme validates the scheme.
func ValidateWebSchemeURL(attribute string, u string) error {

	if u == "" {
		return nil
	}

	uu, err := url.Parse(u)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("invalid url: %s", err))
	}

	switch uu.Scheme {
	case "http", "https":
	default:
		return makeErr(attribute, fmt.Sprintf("invalid url: invalid scheme '%s'. Must be 'http' or 'https'", uu.Scheme))
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

// ValidateDestination validates the destination object.
//
// Deliberately leaner than the backend package's validator of the same name: a
// destination on this side is built by apex from a resolved app component or
// provider rather than supplied by the caller, so the hash-matches-label check
// has nothing to catch. The pairing invariant is still worth asserting, since a
// half-populated destination would mean apex resolved something incompletely.
// ValidatePrincipal is split the same way for the same reason.
func ValidateDestination(destination *Destination) error {

	if (destination.WorkloadGroupLabel == "") != (destination.WorkloadGroupHash == "") {
		return makeErr("workloadGroupHash", "workload group label and hash must both be set or both be empty")
	}

	if (destination.WorkloadGroupSetLabel == "") != (destination.WorkloadGroupSetHash == "") {
		return makeErr("workloadGroupSetHash", "workload group set label and hash must both be set or both be empty")
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

// validateRequestMessages validates that no entry of a request's messages list is
// empty. An empty message is never useful: the extractor turns each entry into its
// own extraction, and the inspector skips empty extractions before analysis, so the
// entry would silently do nothing.
func validateRequestMessages(messages []string) error {

	for i, m := range messages {
		if m == "" {
			return makeErr("messages", fmt.Sprintf("'messages' entry at index %d is empty", i))
		}
	}

	return nil
}

// hasNonEmptyExtraction reports whether at least one extraction carries something
// the analyzer can work with: an extraction with no data is still meaningful when
// it holds tool uses or tool results, which are analyzer inputs in their own
// right. It is a near-mirror of extractor.Extraction.Empty(), which also counts
// annotations — a request extraction cannot carry any, so kind and role alone do
// not make one non-empty.
func hasNonEmptyExtraction(extractions []*ExtractionRequest) bool {

	for _, e := range extractions {

		if e == nil {
			continue
		}

		if len(e.Data) > 0 ||
			len(e.ToolUses) > 0 ||
			len(e.ToolResults) > 0 {
			return true
		}
	}

	return false
}

func validateToolsHaveCategory(tools map[string]*Tool) error {

	for name, tool := range tools {
		if tool.Category == "" || tool.Category == ToolCategoryNone {
			return makeErr("tools", fmt.Sprintf("tool '%s' must have a category set", name))
		}
	}

	return nil
}

// ValidateScanRequest validates the scan request.
//
// The body is deliberately a duplicate of ValidatePoliceRequest: both check the
// same @requestcore attributes, but the generated request types are distinct and
// each carries its own direction enum, so there is nothing to share short of an
// interface that would obscure more than it saves.
func ValidateScanRequest(o *ScanRequest) error {

	if err := validateRequestMessages(o.Messages); err != nil {
		return err
	}

	if err := validateToolsHaveCategory(o.Tools); err != nil {
		return err
	}

	// Scan has nothing to report on without content. Tools alone are not enough:
	// the analyzer runs once per extraction, so a request with no extraction and
	// no message never reaches it, whatever its 'tools' map holds. Police accepts
	// that case, because a moderation can decide on the tools by itself.
	if len(o.Messages) == 0 && !hasNonEmptyExtraction(o.Extractions) {
		return makeErr("messages", "you must set at least one 'messages' entry or one non-empty 'extractions' entry")
	}

	hasDestApp := o.Destination != nil && o.Destination.App != "" && o.Destination.Component != ""
	hasProvider := o.Provider != ""
	isIngress := o.Direction == ScanRequestDirectionIngress

	if hasDestApp && hasProvider {
		return makeErr("provider", "'provider' must not be set when destination app and component are set")
	}

	if isIngress {
		if hasProvider {
			return makeErr("provider", "'provider' must not be set when direction is Ingress")
		}
		if hasDestApp {
			return makeErr("destination", "'destination' app and component must not be set when direction is Ingress; the app component identified by your token is the destination")
		}
	}

	return nil
}

// ValidatePoliceRequest validates the police request.
func ValidatePoliceRequest(o *PoliceRequest) error {

	if err := validateRequestMessages(o.Messages); err != nil {
		return err
	}

	if err := validateToolsHaveCategory(o.Tools); err != nil {
		return err
	}

	// Police must have something to decide on. Unlike scan, tools on their own
	// qualify: a moderation can be written against the tools of the request alone.
	if len(o.Messages) == 0 && len(o.Tools) == 0 && !hasNonEmptyExtraction(o.Extractions) {
		return makeErr("messages", "you must set at least one 'messages' entry, one non-empty 'extractions' entry or one 'tools' entry")
	}

	hasDestApp := o.Destination != nil && o.Destination.App != "" && o.Destination.Component != ""
	hasProvider := o.Provider != ""
	isIngress := o.Direction == PoliceRequestDirectionIngress

	if hasDestApp && hasProvider {
		return makeErr("provider", "'provider' must not be set when destination app and component are set")
	}

	if isIngress {
		if hasProvider {
			return makeErr("provider", "'provider' must not be set when direction is Ingress")
		}
		if hasDestApp {
			return makeErr("destination", "'destination' app and component must not be set when direction is Ingress; the app component identified by your token is the destination")
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
