package api

import (
	"fmt"
	"net/http"

	"go.acuvity.ai/elemental"
)

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

// ValidateRego validates the rego input data.
func ValidateRego(attribute string, code string) error {
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
