package compile

const (
	regoAssignModule = `
package main.assign

default team := ""

team := data.main.team

default policy_info := {}

policy_info := data.main.policy_info

is_provider(providers) if {
	some provider in providers
	provider == input.provider
}

match(subject) if {
	cs := {x | x := input.claims[_]}
	some ands in subject
	ands & cs == ands
}

default policies := []

policies := data.main.policies
`

	regoAccessModule = `
package main.access

default allow := false

allow := data.main.allow

default deny := []

deny := data.main.deny

alerts contains x if some x in data.main.alerts

default minimal_logging := false

minimal_logging := data.main.minimal_logging

default permissive := false

permissive := data.main.permissive

default keywords := []

keywords := data.main.keywords

default analyzers := []

analyzers := data.main.analyzers

default policy_info := {}

policy_info := data.main.policy_info

is_provider(providers) if {
	some provider in providers
	provider == input.provider
}

is_team(teams) if {
	some team in teams
	team == input.team
}

has_prefixed_annotations(prefix, keys) if {
	some key in keys
	input.annotations[concat("_", [prefix, key])] == "true"
}

prefixed_annotation_exists(prefix) if {
	some annotation in object.keys(input.annotations)
	startswith(annotation, prefix)
}

default policies := []

policies := data.main.policies
`

	regoContentModule = `
package main.content

default exceptions := []

exceptions := data.main.exceptions

default warnings := []

warnings := data.main.warnings

redactions[x] if some x in data.main.redactions

alerts contains x if some x in data.main.alerts

decision := {"action": "deny", "reasons": msg} if {
	count(exceptions) > 0
	msg = exceptions
}

decision := {"action": "ask", "reasons": msg} if {
	count(warnings) > 0
	count(exceptions) == 0
	msg = warnings
}

decision := {"action": "allow", "reasons": []} if {
	count(exceptions) == 0
	count(warnings) == 0
}

has_category_group(group) if input.categories[_].group == group

has_category(group, type) if {
	input.categories[_].group == group
	input.categories[_].type == type
}

has_modality_group(group) if input.modalities[_].group == group

has_modality(group, type) if {
	input.modalities[_].group == group
	input.modalities[_].type == type
}

has_topics(topics) if _ = input.topics[topics[_]]

has_languages(languages) if _ = input.languages[languages[_]]

has_piis(piis) if _ = input.piis[piis[_]]

has_keywords(keywords) if _ = input.keywords[keywords[_]]

has_secrets(secrets) if _ = input.secrets[secrets[_]]

has_exploits(exploits) if _ = input.exploits[exploits[_]]

has_prefixed_annotations(prefix, keys) if {
	some key in keys
	input.annotations[concat("_", [prefix, key])] == "true"
}

is_provider(providers) if {
	some provider in providers
	provider == input.provider
}

is_team(teams) if {
	some team in teams
	team == input.team
}

prefixed_annotation_exists(prefix) if {
	some annotation in object.keys(input.annotations)
	startswith(annotation, prefix)
}

default policies := []

policies := data.main.policies
`
)

// GetRegoModuleAssign returns the code for the assign module.
func GetRegoModuleAssign() []byte {
	return []byte(regoAssignModule)
}

// GetRegoModuleAccess returns the code for the access module.
func GetRegoModuleAccess() []byte {
	return []byte(regoAccessModule)
}

// GetRegoModuleContent returns the code for the content module.
func GetRegoModuleContent() []byte {
	return []byte(regoContentModule)
}
