package compile

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"github.com/open-policy-agent/opa/rego"
)

var (

	// ModuleAssign is the module to import to handle rego team policy.
	ModuleAssign = ast.MustParseModuleWithOpts(
		regoAssignModule,
		ast.ParserOptions{
			RegoVersion:       ast.RegoVersion(1),
			AllFutureKeywords: true,
			Capabilities:      ast.CapabilitiesForThisVersion(),
		},
	)
	// ModuleAccess is the module to import to handle rego access policy.
	ModuleAccess = ast.MustParseModuleWithOpts(
		regoAccessModule,
		ast.ParserOptions{
			RegoVersion:       ast.RegoVersion(1),
			AllFutureKeywords: true,
			Capabilities:      ast.CapabilitiesForThisVersion(),
		},
	)

	// ModuleContent is the module to import to handle rego content policy.
	ModuleContent = ast.MustParseModuleWithOpts(
		regoContentModule,
		ast.ParserOptions{
			RegoVersion:       ast.RegoVersion(1),
			AllFutureKeywords: true,
			Capabilities:      ast.CapabilitiesForThisVersion(),
		},
	)
)

// Rego returns a compiler that compiled the given
// policy. It is compiled with the with given modules.
func Rego(policy string, name string, modules ...*ast.Module) (*ast.Compiler, error) {

	name = name + ".rego"

	policy = strings.Replace(policy, "import rego.v1", "", -1) // we force it. so we remove it.

	compiler := ast.NewCompiler().WithUnsafeBuiltins(
		map[string]struct{}{
			ast.HTTPSend.Name:        {},
			ast.NetLookupIPAddr.Name: {},
			ast.OPARuntime.Name:      {},
		},
	)

	module, err := prepareModule("main", policy)
	if err != nil {
		return nil, err
	}

	allModules := map[string]*ast.Module{
		name: module,
	}
	for _, m := range modules {
		allModules[m.Package.String()+".rego"] = m
	}

	compiler.Compile(allModules)

	if compiler.Failed() {
		return nil, fmt.Errorf("unable compile rego module: %w", compiler.Errors)
	}

	return compiler, nil
}

func regoQuery(ctx context.Context, comp *ast.Compiler, query func(*rego.Rego)) (rego.PreparedEvalQuery, error) {

	return rego.New(
		rego.Compiler(comp),
		query,
	).PrepareForEval(ctx)
}

// RegoQueryAssign runs the assign query using the given *ast.Compiler.
func RegoQueryAssign(ctx context.Context, comp *ast.Compiler) (rego.PreparedEvalQuery, error) {
	return regoQuery(
		ctx,
		comp,
		rego.Query(
			fmt.Sprintf("%s; %s; %s",
				"team := data.main.assign.team",
				"policy_info := data.main.assign.policy_info",
				"policies := data.main.assign.policies",
			),
		),
	)
}

// RegoQueryAccess runs the access query using the given *ast.Compiler.
func RegoQueryAccess(ctx context.Context, comp *ast.Compiler) (rego.PreparedEvalQuery, error) {
	return regoQuery(
		ctx,
		comp,
		rego.Query(
			fmt.Sprintf("%s; %s; %s; %s; %s; %s; %s; %s; %s",
				"deny := data.main.access.deny",
				"permissive := data.main.access.permissive",
				"minimal_logging := data.main.access.minimal_logging",
				"allow := data.main.access.allow",
				"keywords := data.main.access.keywords",
				"analyzers := data.main.access.analyzers",
				"policy_info := data.main.access.policy_info",
				"alerts := data.main.access.alerts",
				"policies := data.main.access.policies",
			),
		),
	)
}

// RegoQueryContent runs the content query using the given *ast.Compiler.
func RegoQueryContent(ctx context.Context, comp *ast.Compiler) (rego.PreparedEvalQuery, error) {
	return regoQuery(
		ctx,
		comp,
		rego.Query(
			fmt.Sprintf("%s; %s; %s; %s",
				"decision := data.main.content.decision",
				"redactions := data.main.content.redactions",
				"alerts := data.main.content.alerts",
				"policies := data.main.content.policies",
			),
		),
	)
}

// RegoFormat formats the given rego policy.
func RegoFormat(policy string) (string, error) {

	module, err := prepareModule("main", policy)
	if err != nil {
		return "", err
	}

	formatted, err := format.AstWithOpts(
		module,
		format.Opts{
			RegoVersion: ast.RegoVersion(1),
		},
	)
	if err != nil {
		return "", fmt.Errorf("unable to format rego policy: %w", err)
	}

	return strings.Replace(string(formatted), "import rego.v1\n", "", 1), nil
}

func prepareModule(name string, policy string) (*ast.Module, error) {

	caps := ast.CapabilitiesForThisVersion()
	caps.AllowNet = []string{}

	module, err := ast.ParseModuleWithOpts(
		name,
		policy,
		ast.ParserOptions{
			RegoVersion:       ast.RegoVersion(1),
			AllFutureKeywords: true,
			ProcessAnnotation: false,
			Capabilities:      caps,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to parse rego module: %w", err)
	}

	return module, nil
}
