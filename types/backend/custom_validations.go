package api

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/acuvity/api-go/pkgs/compile"
	"github.com/acuvity/api-go/pkgs/netsafe"
	"github.com/acuvity/api-go/pkgs/sanitize"
	"github.com/globalsign/mgo/bson"
	"github.com/open-policy-agent/opa/ast"
	"go.acuvity.ai/elemental"
)

var ianaChecker netsafe.Checker

func init() {
	var err error
	ianaChecker, err = netsafe.MakeChecker(netsafe.IANAPrivateNetworks, nil)
	if err != nil {
		panic(err)
	}
}

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

// ValidateURLs validates the given value is a list of correct url.
func ValidateURLs(attribute string, u []string) error {

	for i := 0; i < len(u); i++ {
		if err := ValidateURL(attribute, u[i]); err != nil {
			return err
		}
	}
	return nil
}

// ValidateDuration validates the time.Duration input.
func ValidateDuration(attribute string, duration string) error {
	if duration == "" {
		return nil
	}
	_, err := time.ParseDuration(duration)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("Attribute '%s' must be valid duration (example: 1h or 30s)", attribute))
	}

	return nil
}

// ValidateEmail validates an emails.
func ValidateEmail(attribute string, email string) error {

	if email == "" {
		return nil
	}

	if _, err := mail.ParseAddress(email); err != nil {
		return makeErr(attribute, fmt.Sprintf("Attribute '%s' contains invalid email '%s'", attribute, email))
	}

	return nil
}

// ValidateEmails validates the list of emails.
func ValidateEmails(attribute string, emails []string) error {

	if len(emails) == 0 {
		return nil
	}

	for i, email := range emails {
		if email == "" {
			return makeErr(attribute, fmt.Sprintf("Attribute '%s' contains an empty email at index %d", attribute, i))
		}

		if err := ValidateEmail(attribute, email); err != nil {
			return err
		}
	}

	return nil
}

// ValidateClientTokenValidity validates the client token is a correct duration and does not exceed 1y.
func ValidateClientTokenValidity(attribute string, duration string) error {

	v, err := time.ParseDuration(duration)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("Attribute '%s' must be valid duration (example: 1h or 30s)", attribute))
	}

	if v > 8760*time.Hour {
		return makeErr(attribute, fmt.Sprintf("Attribute '%s' must be not exceed 1y (8760h)", attribute))
	}

	return nil
}

// ValidateAuthorizationSubject makes sure api authorization subject is at least secured a bit.
func ValidateAuthorizationSubject(attribute string, subject [][]string) error {

	for i, ands := range subject {

		for _, claim := range ands {

			parts := strings.SplitN(claim, "=", 2)
			if len(parts) != 2 {
				return makeErr(attribute, fmt.Sprintf("Subject claims '%s' on line %d is an invalid tag", claim, i+1))
			}
			if parts[1] == "" {
				return makeErr(attribute, fmt.Sprintf("Subject claims '%s' on line %d has no value", claim, i+1))
			}
		}
	}

	return nil
}

var tagRegex = regexp.MustCompile(`^[^= ]+=.+`)

// ValidateTagsExpression validates an [][]string is a valid tag expression.
func ValidateTagsExpression(attribute string, expression [][]string) error {

	for _, tags := range expression {

		for _, tag := range tags {

			if len([]byte(tag)) >= 1024 {
				return makeErr(attribute, fmt.Sprintf("'%s' must be less than 1024 bytes", tag))
			}
			if !tagRegex.MatchString(tag) {
				return makeErr(attribute, fmt.Sprintf("'%s' must contain at least one '=' symbol separating two valid words", tag))
			}

		}
	}

	return nil
}

// ValidateContentPolicy validates the entire content policy object.
func ValidateContentPolicy(contentPolicy *ContentPolicy) error {

	for _, moderation := range contentPolicy.Moderations {
		if moderation.Action == ModerationActionNone && moderation.AlertDefinition == "" && !moderation.Redact {
			return makeErr("action", "You must have at least redaction or alert definition set")
		}

		if moderation.Redact {
			var hasRedactedValue bool
			for _, predicate := range moderation.Predicates {
				if predicate.Key != PredicateKeyKeywords && predicate.Key != PredicateKeyPIIs && predicate.Key != PredicateKeySecrets {
					continue
				}
				if predicate.Operator == PredicateOperatorEqualsOrGreaterThan {
					return makeErr("predicates", fmt.Sprintf("Cannot pair %s '%s' with redaction; use '%s' or '%s' instead",
						predicate.Key, predicate.Operator, PredicateOperatorAny, PredicateOperatorNotEmpty,
					))
				}
				hasRedactedValue = true
				break
			}
			if !hasRedactedValue {
				return makeErr("predicates", "'Redact' must have at least one keyword, PII, or secret tied to it")
			}
		}

		if moderation.Action == ModerationActionWarn && strings.ReplaceAll(moderation.Message, " ", "") == "" {
			return makeErr("message", "'Message' must not be empty when 'Action' is 'Warn'")
		}

		if moderation.Action == ModerationActionBlock && strings.ReplaceAll(moderation.Message, " ", "") == "" {
			return makeErr("message", "'Message' must not be empty when 'Action' is 'Block'")
		}
	}

	return nil
}

// ValidateAccessPolicy validates the entire access policy object.
func ValidateAccessPolicy(accessPolicy *AccessPolicy) error {

	if accessPolicy.Action == AccessPolicyActionAllow && accessPolicy.AlertDefinition != "" {
		return makeErr("alertDefinition", fmt.Sprintf("you cannot set an alert definition if the access decision is '%s'", accessPolicy.Action))
	}

	if accessPolicy.Action == AccessPolicyActionDeny && len(accessPolicy.ContentPolicies) != 0 {
		return makeErr("contentPolicies", fmt.Sprintf("you cannot set content policies if the access decision is '%s'", accessPolicy.Action))
	}

	matches := map[string]any{}
	for _, cpol := range accessPolicy.ContentPolicies {
		if _, ok := matches[cpol]; !ok {
			matches[cpol] = nil
			continue
		}
		return makeErr("contentPolicies", fmt.Sprintf("you cannot have duplicate content policies applied ('%s')", cpol))
	}

	predicates := map[string]any{}
	for _, criteria := range accessPolicy.Match {

		keyop := fmt.Sprintf("%s-%s", criteria.Key, criteria.Operator)
		if _, ok := predicates[keyop]; !ok {
			predicates[keyop] = nil
			continue
		}
		return makeErr("match", fmt.Sprintf("'%s' cannot have multiple entries for the same operator '%s'", criteria.Key, criteria.Operator))
	}

	return nil
}

// ValidateAccessPolicyTopics validates the topics of an access policy.
func ValidateAccessPolicyTopics(attribute string, forbiddenTopics []string) error {

	for _, topic := range forbiddenTopics {

		if strings.Contains(topic, "<SEP>") {
			return makeErr(attribute, fmt.Sprintf("'%s' can not contain <SEP>", topic))
		}
	}

	return nil
}

// ValidateProvider validates the entire provider objects
func ValidateProvider(provider *Provider) error {

	hosts := make([]string, len(provider.Hosts))
	for i, h := range provider.Hosts {
		hosts[i] = h.Name
	}

	for i, extractor := range provider.InputExtractors {
		if len(extractor.Hosts) != 0 {
			var matched bool
			for _, h := range extractor.Hosts {
				if slices.Contains(hosts, h) {
					matched = true
				}
			}
			if !matched {
				return makeErr("hosts", fmt.Sprintf("inputExtractor[%d].hosts is not defined in the provider hosts list", i))
			}
		}

		if err := extractor.Validate(); err != nil {
			return makeErr("hosts", fmt.Sprintf("inputExtractor[%d]: %s", i, err))
		}
	}

	for i, extractor := range provider.OutputExtractors {
		if len(extractor.Hosts) != 0 {
			var matched bool
			for _, h := range extractor.Hosts {
				if slices.Contains(hosts, h) {
					matched = true
				}
			}
			if !matched {
				return makeErr("hosts", fmt.Sprintf("outputExtractor[%d].hosts is not defined in the provider hosts list", i))
			}
		}

		if err := extractor.Validate(); err != nil {
			return makeErr("hosts", fmt.Sprintf("outputExtractor[%d]: %s", i, err))
		}
	}

	for i, mapper := range provider.Mappers {
		if len(mapper.Hosts) != 0 {
			var matched bool
			for _, h := range mapper.Hosts {
				if slices.Contains(hosts, h) {
					matched = true
				}
			}
			if !matched {
				return makeErr("hosts", fmt.Sprintf("mapper[%d].hosts is not defined in the provider hosts list", i))
			}
		}
	}

	for i, injectors := range provider.Injectors {
		if len(injectors.Hosts) != 0 {
			var matched bool
			for _, h := range injectors.Hosts {
				if slices.Contains(hosts, h) {
					matched = true
				}
			}
			if !matched {
				return makeErr("hosts", fmt.Sprintf("injectors[%d].hosts is not defined in the provider hosts list", i))
			}
		}
	}

	return nil
}

// ValidateExtractor validates the given Extractor.
func ValidateExtractor(extractor *Extractor) error {

	if extractor.Deanonymize && extractor.Anonymization == ExtractorAnonymizationFixedSize {
		return makeErr("Deanonymize", fmt.Sprintf("Anonymization must be VariableSize to enable Deanonymization. got: %s", extractor.Anonymization))
	}

	return nil
}

// ValidateRestrictedIP validate a single IP or host to make sure it is not
// in a IANA defined private network.
func ValidateRestrictedIP(attribute string, host string) error {

	if err := ianaChecker(host); err != nil {
		return makeErr(attribute, fmt.Sprintf("Restricted IP: %s", err))
	}

	return nil
}

// ValidateRestrictedIPs validate a list of IPs or hosts to make sure it is not
// in a IANA defined private network.
func ValidateRestrictedIPs(attribute string, hosts []string) error {

	for _, h := range hosts {
		if err := ianaChecker(h); err != nil {
			return makeErr(attribute, fmt.Sprintf("Restricted IP: %s", err))
		}
	}

	return nil
}

// ValidateFilter validates the given input is an elemental filter.
func ValidateFilter(attribute string, filter string) error {

	if _, err := elemental.NewFilterParser(filter).Parse(); err != nil {
		return makeErr(attribute, fmt.Sprintf("unable to validate filter: %s", err))
	}

	return nil
}

// ValidateFriendlyName checks if the given friendly name is valid.
func ValidateFriendlyName(attribute string, name string) error {

	if sanitize.Name(name) == "" {
		return makeErr(attribute, fmt.Sprintf("provided name ('%s') must contain as least one alphanumeric character, '-' or '_'.", name))
	}

	return nil
}

// ValidateObjectIDs validates if the provided list of IDs are valid bson ObjectIDs.
func ValidateObjectIDs(attribute string, ids []string) error {

	for i, id := range ids {
		if id == "" {
			return makeErr(attribute, fmt.Sprintf("empty ID at index %d in list", i))
		}

		if err := ValidateObjectID(attribute, id); err != nil {
			return err
		}
	}

	return nil
}

// ValidateObjectID validates the given ID is a valid bson ObjectID.
func ValidateObjectID(attribute string, id string) error {

	if id == "" {
		return nil
	}

	if !bson.IsObjectIdHex(id) {
		return makeErr(attribute, fmt.Sprintf("invalid object ID '%s'", id))
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

// ValidateLua validates the lua input data.
func ValidateLua(attribute string, code string) error {

	if len(code) == 0 {
		return nil
	}

	if _, err := compile.Lua([]byte(code)); err != nil {
		return makeErr(attribute, fmt.Sprintf("Unable to compile lua: %s", err))
	}

	return nil
}

// ValidatePredicate validates the given Predicate.
func ValidatePredicate(p *Predicate) error {

	o := p.Operator
	v := p.Values

	switch p.Key {
	case PredicateKeyProvider:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny {
			return makeErr("operator", "Key 'Provider' only supports operator 'Any' and 'NotAny'")
		}
		if len(v) == 0 {
			return makeErr("values", "'Provider' must have at least one value")
		}
		for _, v := range v {
			strVal, ok := v.(string)
			if !ok {
				return makeErr("values", "Key 'Provider' only supports string values")
			}
			if strings.Contains(strVal, `"`) {
				return makeErr("values", "Key 'Provider' must not have a value that contains a quote")
			}
		}

	case PredicateKeyTeam:
		if o != PredicateOperatorAny {
			return makeErr("operator", "Key 'Team' only supports operator 'Any'")
		}
		if len(v) == 0 {
			return makeErr("values", "'Team' must have at least one value")
		}
		for _, v := range v {
			strVal, ok := v.(string)
			if !ok {
				return makeErr("values", "Key 'Team' only supports string values")
			}
			if strings.Contains(strVal, `"`) {
				return makeErr("values", "Key 'Team' must not have a value that contains a quote")
			}
		}

	case PredicateKeyWorkspace:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'Workspace' only supports operators 'Any', 'NotAny', 'Empty' and 'NotEmpty")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'Workspace' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'Workspace' only supports string values when operator is 'Any' or 'NotAny'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'Workspace' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'Workspace' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeyExploits:
		if o != PredicateOperatorAny && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'Exploits' only supports operators 'Any', and 'NotEmpty")
		}
		if o == PredicateOperatorAny {
			if len(v) == 0 {
				return makeErr("values", "'Exploits' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'Exploits' only supports string values when operator is 'Any'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'Exploits' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'Exploits' only supports no values when operation is 'NotEmpty'")
			}
		}

	case PredicateKeyPlugin:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'Plugin' only supports operators 'Any' 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'Plugin' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'Plugin' only supports string values when operator is 'Any' or 'NotAny'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'Plugin' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'Plugin' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeyConfidentiality:
		if o != PredicateOperatorEqualsOrLesserThan && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'Confidentiality' only supports operators 'EqualsOrGreaterThan' and 'EqualsOrLesserThan'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'Confidentiality' only supports one single value")
		}
		switch t := p.Values[0].(type) {
		case int, float64, uint64, int64:
		default:
			return makeErr("values", fmt.Sprintf("Key 'Confidentiality' only supports float value. Found '%T'", t))
		}

	case PredicateKeyRelevance:
		if o != PredicateOperatorEqualsOrLesserThan && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'Relevance' only supports operators 'EqualsOrGreaterThan' and 'EqualsOrLesserThan'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'Relevance' only supports one single value")
		}
		switch t := p.Values[0].(type) {
		case int, float64, uint64, int64:
		default:
			return makeErr("values", fmt.Sprintf("Key 'Relevance' only supports float value. Found '%T'", t))
		}

	case PredicateKeyKeywords:
		if o != PredicateOperatorAny && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'Keywords' only supports operators 'Any' and 'EqualsOrGreaterThan'")
		}
		if len(v) == 0 {
			return makeErr("values", "'Keywords' must have at least one value")
		}
		if o == PredicateOperatorAny {
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'Keywords' only supports string values when operator is 'Any'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'Keywords' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorEqualsOrGreaterThan {
			if len(v) != 1 {
				return makeErr("values", "Key 'Keywords' only supports one single value for 'EqualsOrGreaterThan'")
			}
			switch t := p.Values[0].(type) {
			case int, uint64, int64:
			case float64:
				p.Values[0] = int(p.Values[0].(float64))
			default:
				return makeErr("values", fmt.Sprintf("Key 'Keywords' only supports int value for 'EqualsOrGreaterThan'. Found '%T'", t))
			}
		}

	case PredicateKeyPIIs:
		if o != PredicateOperatorAny && o != PredicateOperatorNotEmpty && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'PIIs' only supports operators 'Any', 'NotEmpty' and 'EqualsOrGreaterThan'")
		}
		if o == PredicateOperatorAny {
			if len(v) == 0 {
				return makeErr("values", "'PIIs' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'PIIs' only supports string values")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'PIIs' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'PIIs' only supports no values when operation is 'NotEmpty'")
			}
		}
		if o == PredicateOperatorEqualsOrGreaterThan {
			if len(v) != 1 {
				return makeErr("values", "Key 'PIIs' only supports one single value for 'EqualsOrGreaterThan'")
			}
			switch t := p.Values[0].(type) {
			case int, uint64, int64:
			case float64:
				p.Values[0] = int(p.Values[0].(float64))
			default:
				return makeErr("values", fmt.Sprintf("Key 'PIIs' only supports int value for 'EqualsOrGreaterThan'. Found '%T'", t))
			}
		}

	case PredicateKeySecrets:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorNotEmpty && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'Secrets' only supports operators 'Any', 'NotAny', 'NotEmpty' and 'EqualsOrGreaterThan'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'Secrets' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'Secrets' only supports string values")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'Secrets' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'Secrets' only supports no values when operation is 'NotEmpty'")
			}
		}
		if o == PredicateOperatorEqualsOrGreaterThan {
			if len(v) != 1 {
				return makeErr("values", "Key 'Secrets' only supports one single value for 'EqualsOrGreaterThan'")
			}
			switch t := p.Values[0].(type) {
			case int, uint64, int64:
			case float64:
				p.Values[0] = int(p.Values[0].(float64))
			default:
				return makeErr("values", fmt.Sprintf("Key 'Secrets' only supports int value for 'EqualsOrGreaterThan'. Found '%T'", t))
			}
		}

	case PredicateKeyTopics:
		if o != PredicateOperatorAny {
			return makeErr("operator", "Key 'Topics' only supports operator 'Any'")
		}
		if len(v) == 0 {
			return makeErr("values", "'Topics' must have at least one value")
		}
		for _, v := range v {
			strVal, ok := v.(string)
			if !ok {
				return makeErr("values", "Key 'Topics' only supports string values")
			}
			if strings.Contains(strVal, `"`) {
				return makeErr("values", "Key 'Topics' must not have a value that contains a quote")
			}
		}

	case PredicateKeyLanguages:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorNotEmpty && o != PredicateOperatorEmpty {
			return makeErr("operator", "Key 'Langues' only supports operators 'Any', 'NotAny', 'Empty', 'NotEmpty'")
		}

		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'Languages' must have at least one value")
			}
		}

		for _, v := range v {
			strVal, ok := v.(string)
			if !ok {
				return makeErr("values", "Key 'Languages' only supports string values")
			}
			if strings.Contains(strVal, `"`) {
				return makeErr("values", "Key 'Languages' must not have a value that contains a quote")
			}
		}

	case PredicateKeySize:
		if o != PredicateOperatorEqualsOrLesserThan && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'Size' only supports operators 'EqualsOrGreaterThan' and 'EqualsOrLesserThan'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'Size' only supports one single value")
		}
		switch t := p.Values[0].(type) {
		case int, uint64, int64:
		case float64:
			p.Values[0] = int(p.Values[0].(float64))
		default:
			return makeErr("values", fmt.Sprintf("Key 'Size' only supports int value. Found '%T'", t))
		}

	case PredicateKeyCategories:
		if o != PredicateOperatorEquals && o != PredicateOperatorNotEquals {
			return makeErr("operator", "Key 'Categories' only supports operator 'Equals' and 'NotEquals'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'Categories' only supports one single value")
		}
		if _, ok := p.Values[0].(string); !ok {
			return makeErr("values", "Key 'Categories' only supports string value")
		}

	case PredicateKeyModality:
		if o != PredicateOperatorEquals && o != PredicateOperatorNotEquals {
			return makeErr("operator", "Key 'Modality' only supports operator 'Equals' and 'NotEquals'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'Modality' only supports one single value")
		}
		if _, ok := p.Values[0].(string); !ok {
			return makeErr("values", "Key 'Modality' only supports string value")
		}

	case PredicateKeyModel:
		if o != PredicateOperatorEquals && o != PredicateOperatorNotEquals {
			return makeErr("operator", "Key 'Model' only supports operator 'Equals' and 'NotEquals'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'Model' only supports one single value")
		}
		if _, ok := p.Values[0].(string); !ok {
			return makeErr("values", "Key 'Model' only supports string value")
		}

	case PredicateKeyTools:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'Tools' only supports operators 'Any' 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'Tools' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'Tools' only supports string values when operator is 'Any' or 'NotAny'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'Tools' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'Tools' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}
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

// ValidateAlertDefinition validates the entire alert definition object.
func ValidateAlertDefinition(alertDefinition *AlertDefinition) error {

	matches := map[string]any{}
	for _, name := range alertDefinition.Sinks {
		if _, ok := matches[name]; !ok {
			matches[name] = nil
			continue
		}
		return makeErr("sinks", fmt.Sprintf("you cannot have duplicate sinks applied ('%s')", name))
	}

	if alertDefinition.Trigger != nil {
		if alertDefinition.Trigger.Occurrences > 25 {
			return makeErr("trigger", fmt.Sprintf("you cannot set occurrences ('%d') higher than 25. Please consider setting a cooldown in combination.", alertDefinition.Trigger.Occurrences))
		}
	}

	return nil
}

// ValidateSink validates the sink object.
func ValidateSink(sink *Sink) error {

	switch sink.Type {
	case SinkTypeEmail:
		if sink.Email == nil {
			return makeErr("email", "'Email' must have its configuration defined.")
		}
	case SinkTypePagerDuty:
		if sink.PagerDuty == nil {
			return makeErr("pagerDuty", "'PagerDuty' must have its configuration defined.")
		}
	case SinkTypeSlack:
		if sink.Slack == nil {
			return makeErr("slack", "'Slack' must have its configuration defined.")
		}
	case SinkTypeSplunk:
		if sink.Splunk == nil {
			return makeErr("splunk", "'Splunk' must have its configuration defined.")
		}
	}

	return nil
}

// ValidateApp validates the app object
func ValidateApp(app *App) error {

	m := map[string]struct{}{}
	for _, tier := range app.Tiers {
		if tier.Name == "_default" {
			return makeErr("name", "_default is a reserved tier name")
		}

		if _, ok := m[tier.Name]; ok {
			return makeErr("name", fmt.Sprintf("another tier is already named '%s'", tier.Name))
		}
		m[tier.Name] = struct{}{}
	}

	return nil
}

// ValidatePEM validates a string contains a PEM.
func ValidatePEM(attribute string, pemdata string) error {

	if pemdata == "" {
		return nil
	}

	var i int
	var block *pem.Block
	rest := []byte(pemdata)

	for {
		block, rest = pem.Decode(rest)

		if block == nil {
			return makeErr(attribute, fmt.Sprintf("Unable to decode PEM number %d", i))
		}

		if len(rest) == 0 {
			return nil
		}
		i++
	}
}

// ValidateAgentConfig validates the agent configuration object.
func ValidateAgentConfig(agentConfig *AgentConfig) error {

	// Ping interval
	d, err := time.ParseDuration(agentConfig.PingInterval)
	if err != nil {
		return makeErr("pingInterval", "'PingInterval' must be a valid duration (ex: 10m or 1h).")
	}

	if d < 5*time.Minute {
		return makeErr("pingInterval", "'PingInterval' can not be lower than 5m")
	}

	// Port
	if agentConfig.ListeningPort != "" {
		port, err := strconv.Atoi(agentConfig.ListeningPort)

		if err != nil {
			return makeErr("listeningPort", "Invalid 'ListeningPort'. It should be in the range 1024-49151.")
		}

		if port < 1024 || port > 49151 {
			return makeErr("listeningPort", "'ListeningPort' should be in the range 1024-49151.")
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
