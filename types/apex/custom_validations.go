package api

import (
	"fmt"
	"net/http"

	"github.com/acuvity/api-go/pkgs/compile"
	"github.com/open-policy-agent/opa/ast"
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

	if len(code) == 0 {
		return nil
	}

	var module *ast.Module
	switch attribute {
	case "assignPolicy":
		module = compile.ModuleAssign
	case "accessPolicy":
		module = compile.ModuleAccess
	case "contentPolicy":
		module = compile.ModuleContent
	}

	if _, err := compile.Rego(code, "test", module); err != nil {
		return makeErr(attribute, fmt.Sprintf("Unable to compile rego: %s", err))
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
