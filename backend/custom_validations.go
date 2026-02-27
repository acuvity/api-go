package api

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/globalsign/mgo/bson"
	"github.com/robfig/cron/v3"
	a3sapi "go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/elemental"
	"go.opentelemetry.io/collector/pdata/ptrace"
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
	case "http", "https", "ws", "wss":
	case "":
		return makeErr(attribute, "invalid url: missing scheme")
	default:
		return makeErr(attribute, "invalid url: invalid scheme")
	}

	if uu.Hostname() == "" {
		return makeErr(attribute, "invalid url: missing hostname")
	}

	return nil
}

// ValidateURLs validates the given value is a list of correct url.
func ValidateURLs(attribute string, u []string) error {

	for i := range len(u) {
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

// ValidateTagsExpression validates an [][]string is a valid tag expression.
func ValidateTagsExpression(attribute string, expression [][]string) error {

	for _, tags := range expression {

		for _, tag := range tags {

			if err := ValidateTag(attribute, tag); err != nil {
				return err
			}
		}
	}

	return nil
}

var tagRegex = regexp.MustCompile(`^[^= ]+=.+`)

// ValidateTag validates a single tag.
func ValidateTag(attribute string, tag string) error {

	if strings.TrimSpace(tag) != tag {
		return makeErr(attribute, fmt.Sprintf("'%s' must not contain any leading or trailing spaces", tag))
	}

	if len([]byte(tag)) >= 1024 {
		return makeErr(attribute, fmt.Sprintf("'%s' must be less than 1024 bytes", tag))
	}

	if !tagRegex.MatchString(tag) {
		return makeErr(attribute, fmt.Sprintf("'%s' must contain at least one '=' symbol separating two valid words", tag))
	}

	return nil
}

// ValidateContentPolicy validates the entire content policy object.
func ValidateContentPolicy(contentPolicy *ContentPolicy) error {

	index := 0
	for i, moderation := range contentPolicy.Moderations {

		if err := ValidateToolMisalignmentExploit(moderation, i); err != nil {
			return err
		}

		if moderation.Redact {
			var hasRedactedValue bool
			for j, predicate := range moderation.Predicates {
				if predicate.Key != PredicateKeyKeywords && predicate.Key != PredicateKeyPIIs && predicate.Key != PredicateKeySecrets && predicate.Key != PredicateKeyCustomDataTypes {
					continue
				}
				if predicate.Operator == PredicateOperatorEqualsOrGreaterThan {
					return makeErr(fmt.Sprintf("moderation/%d/predicates/%d", i, j), fmt.Sprintf("Cannot pair %s '%s' with redaction; use '%s' or '%s' instead",
						predicate.Key, predicate.Operator, PredicateOperatorAny, PredicateOperatorNotEmpty,
					))
				}
				hasRedactedValue = true
				index = j
				break
			}
			if !hasRedactedValue {
				return makeErr(fmt.Sprintf("moderation/%d/predicates/%d", i, index), "'Redact' must have at least one keyword, PII, CDT or secret tied to it")
			}
		}

		if moderation.Action == ModerationActionWarn && strings.ReplaceAll(moderation.Message, " ", "") == "" {
			return makeErr(fmt.Sprintf("moderation/%d/message", i), "'Message' must not be empty when 'Action' is 'Warn'")
		}

		if moderation.Action == ModerationActionBlock && strings.ReplaceAll(moderation.Message, " ", "") == "" {
			return makeErr(fmt.Sprintf("moderation/%d/message", i), "'Message' must not be empty when 'Action' is 'Block'")
		}
	}

	return nil
}

// ValidateAccessPolicy validates the entire access policy object.
func ValidateAccessPolicy(accessPolicy *AccessPolicy) error {

	if accessPolicy.Action == AccessPolicyActionAllow && accessPolicy.AlertDefinition != "" {
		return makeErr("alertDefinition", fmt.Sprintf("you cannot set an alert definition if the access decision is '%s'", accessPolicy.Action))
	}

	if (accessPolicy.Action == AccessPolicyActionDeny || accessPolicy.Action == AccessPolicyActionRedirect) && len(accessPolicy.ContentPolicies) != 0 {
		return makeErr("contentPolicies", fmt.Sprintf("you cannot set content policies if the access decision is '%s'", accessPolicy.Action))
	}

	if accessPolicy.Action == AccessPolicyActionRedirect && accessPolicy.RedirectMessage == "" {
		return makeErr("redirectMessage", fmt.Sprintf("you must set 'redirectMessage' if the access decision is '%s'", accessPolicy.Action))
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

	if provider != nil && strings.HasPrefix(provider.Name, "appc:") {
		return makeErr("name", "provider name must not start with reserved prefix 'appc:'")
	}

	hosts := make(map[string]struct{}, len(provider.Hosts))
	for _, h := range provider.Hosts {
		hosts[h.Name] = struct{}{}
	}

	for i, extractor := range provider.Extractors {
		if len(extractor.Hosts) != 0 {
			for _, h := range extractor.Hosts {
				if _, ok := hosts[h]; !ok {
					return makeErr("extractors", fmt.Sprintf("extractors[%d].hosts '%s' is not defined in the provider hosts list", i, h))
				}
			}
		}

		if err := extractor.Validate(); err != nil {
			return err
		}
	}

	for i, mapper := range provider.Mappers {
		if len(mapper.Hosts) != 0 {
			for _, h := range mapper.Hosts {
				if _, ok := hosts[h]; !ok {
					return makeErr("hosts", fmt.Sprintf("mapper[%d].hosts '%s' is not defined in the provider hosts list", i, h))
				}
			}
		}

		if err := mapper.Validate(); err != nil {
			return err
		}
	}

	for i, injector := range provider.Injectors {
		if len(injector.Hosts) != 0 {
			for _, h := range injector.Hosts {
				if _, ok := hosts[h]; !ok {
					return makeErr("hosts", fmt.Sprintf("injectors[%d].hosts '%s' is not defined in the provider hosts list", i, h))
				}
			}
		}

		if err := injector.Validate(); err != nil {
			return err
		}
	}

	if provider.ErrorTransformer != nil {
		if err := provider.ErrorTransformer.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// ValidateProviderTeamName validates the entire provider team name
func ValidateProviderTeamName(attribute string, name string) error {
	if name == "UNASSIGNED" {
		return makeErr("name", "'UNASSIGNED' is a reserved name")
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

// ValidateExtractorRef validates the given Extractor.
func ValidateExtractorRef(extractor *ExtractorRef) error {

	if extractor.Ref == "" && extractor.Def == nil {
		return makeErr("ref", "You must set one ref or one def")
	}

	if extractor.Ref != "" && extractor.Def != nil {
		return makeErr("ref", "You must only set either one ref or one def")
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

// ValidateTrimmed checks if the given property have no leading and trailing spaces.
func ValidateTrimmed(attribute string, value string) error {

	t := strings.TrimSpace(value)

	if t == "" {
		return makeErr(attribute, fmt.Sprintf("%s must not contain just white space.", attribute))
	}

	if t != value {
		return makeErr(attribute, fmt.Sprintf("%s must not contain any leading or trailing spaces.", attribute))
	}

	return nil
}

// ValidatePredicate validates the given Predicate.
func ValidatePredicate(p *Predicate) error {

	o := p.Operator
	v := p.Values

	switch p.Key {
	case PredicateKeyDstApp:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'DstApp' only supports operators 'Any', 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'DstApp' must have at least one value")
			}
			m := make(map[string]struct{}, len(v))
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'DstApp' only supports string values")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'DstApp' must not have a value that contains a quote")
				}
				if _, ok := m[strVal]; ok {
					return makeErr("values", "Key 'DstApp' must not have duplicate values")
				}
				m[strVal] = struct{}{}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'DstApp' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeyDstComponent:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'DstComponent' only supports operators 'Any', 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'DstComponent' must have at least one value")
			}
			m := make(map[string]struct{}, len(v))
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'DstComponent' only supports string values")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'DstComponent' must not have a value that contains a quote")
				}
				if _, ok := m[strVal]; ok {
					return makeErr("values", "Key 'DstComponent' must not have duplicate values")
				}
				m[strVal] = struct{}{}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'DstComponent' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeyDstIPRange:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny {
			return makeErr("operator", "Key 'DstIPRange' only supports operator 'Any' and 'NotAny'")
		}
		if len(v) == 0 {
			return makeErr("values", "'DstIPRange' must have at least one value")
		}
		m := make(map[string]struct{}, len(v))
		for _, v := range v {
			strVal, ok := v.(string)
			if !ok {
				return makeErr("values", "Key 'DstIPRange' only supports string values")
			}
			if _, _, err := net.ParseCIDR(strVal); err != nil {
				return makeErr("values", fmt.Sprintf("Key 'DstIPRange' only supports valid CIDR values. Found '%s'. Error while parsing: %s", strVal, err))
			}
			if _, ok := m[strVal]; ok {
				return makeErr("values", "Key 'DstIPRange' must not have duplicate values")
			}
			m[strVal] = struct{}{}
		}

	case PredicateKeyIsIngress:
		if o != PredicateOperatorEquals && o != PredicateOperatorNotEquals {
			return makeErr("operator", "Key 'IsIngress' only supports operator 'Equals' and 'NotEquals")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'IsIngress' only supports one single value")
		}
		if _, ok := p.Values[0].(bool); !ok {
			return makeErr("values", "Key 'IsIngress' only supports boolean value")
		}

	case PredicateKeySrcApp:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'SrcApp' only supports operators 'Any', 'NotAny', 'Empty' and 'NotEmpty")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'SrcApp' must have at least one value")
			}
			m := make(map[string]struct{}, len(v))
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'SrcApp' only supports string values")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'SrcApp' must not have a value that contains a quote")
				}
				if _, ok := m[strVal]; ok {
					return makeErr("values", "Key 'SrcApp' must not have duplicate values")
				}
				m[strVal] = struct{}{}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'SrcApp' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeySrcComponent:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'SrcComponent' only supports operators 'Any', 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'SrcComponent' must have at least one value")
			}
			m := make(map[string]struct{}, len(v))
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'SrcComponent' only supports string values")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'SrcComponent' must not have a value that contains a quote")
				}
				if _, ok := m[strVal]; ok {
					return makeErr("values", "Key 'SrcComponent' must not have duplicate values")
				}
				m[strVal] = struct{}{}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'SrcComponent' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeySrcIPRange:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny {
			return makeErr("operator", "Key 'SrcIPRange' only supports operator 'Any' and 'NotAny'")
		}
		if len(v) == 0 {
			return makeErr("values", "'SrcIPRange' must have at least one value")
		}
		m := make(map[string]struct{}, len(v))
		for _, v := range v {
			strVal, ok := v.(string)
			if !ok {
				return makeErr("values", "Key 'SrcIPRange' only supports string values")
			}
			if _, _, err := net.ParseCIDR(strVal); err != nil {
				return makeErr("values", fmt.Sprintf("Key 'SrcIPRange' only supports valid CIDR values. Found '%s'. Error while parsing: %s", strVal, err))
			}
			if _, ok := m[strVal]; ok {
				return makeErr("values", "Key 'SrcIPRange' must not have duplicate values")
			}
			m[strVal] = struct{}{}
		}

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
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny {
			return makeErr("operator", "Key 'Team' only supports operator 'Any' and 'NotAny'")
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

	case PredicateKeyMalcontents:
		if o != PredicateOperatorAny && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'Malcontents' only supports operators 'Any', and 'NotEmpty")
		}
		if o == PredicateOperatorAny {
			if len(v) == 0 {
				return makeErr("values", "'Malcontents' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'Malcontents' only supports string values when operator is 'Any'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'Malcontents' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'Malcontents' only supports no values when operation is 'NotEmpty'")
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

	case PredicateKeyCustomDataTypes:
		if o != PredicateOperatorAny && o != PredicateOperatorNotEmpty && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'CustomDataTypes' only supports operators 'Any', 'NotEmpty' and 'EqualsOrGreaterThan'")
		}
		if o == PredicateOperatorAny {
			if len(v) == 0 {
				return makeErr("values", "'CustomDataTypes' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'CustomDataTypes' only supports string values")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'CustomDataTypes' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'CustomDataTypes' only supports no values when operation is 'NotEmpty'")
			}
		}
		if o == PredicateOperatorEqualsOrGreaterThan {
			if len(v) != 1 {
				return makeErr("values", "Key 'CustomDataTypes' only supports one single value for 'EqualsOrGreaterThan'")
			}
			switch t := p.Values[0].(type) {
			case int, uint64, int64:
			case float64:
				p.Values[0] = int(p.Values[0].(float64))
			default:
				return makeErr("values", fmt.Sprintf("Key 'CustomDataTypes' only supports int value for 'EqualsOrGreaterThan'. Found '%T'", t))
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
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEquals && o != PredicateOperatorNotEquals {
			return makeErr("operator", "Key 'Categories' only supports operator 'Any' and 'NotAny'")
		}
		if len(p.Values) < 1 {
			return makeErr("values", "Key 'Categories' must have at least one value")
		}
		for _, v := range p.Values {
			if _, ok := v.(string); !ok {
				return makeErr("values", "Key 'Categories' only supports string value")
			}
		}

	case PredicateKeyModality:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEquals && o != PredicateOperatorNotEquals {
			return makeErr("operator", "Key 'Modality' only supports operator 'Any' and 'NotAny'")
		}
		if len(p.Values) < 1 {
			return makeErr("values", "Key 'Modality' must have at least one value")
		}
		for _, v := range p.Values {
			if _, ok := v.(string); !ok {
				return makeErr("values", "Key 'Modality' only supports string value")
			}
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

	case PredicateKeyToolUses:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'ToolUses' only supports operators 'Any' 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'ToolUses' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'ToolUses' only supports string values when operator is 'Any' or 'NotAny'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'ToolUses' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'ToolUses' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeyMCPGateway:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'MCPGateway' only supports operators 'Any' 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'MCPGateway' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'MCPGateway' only supports string values when operator is 'Any' or 'NotAny'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'MCPGateway' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'MCPGateway' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeyMCPServer:
		if o != PredicateOperatorAny && o != PredicateOperatorNotAny && o != PredicateOperatorEmpty && o != PredicateOperatorNotEmpty {
			return makeErr("operator", "Key 'MCPServer' only supports operators 'Any' 'NotAny', 'Empty' and 'NotEmpty'")
		}
		if o == PredicateOperatorAny || o == PredicateOperatorNotAny {
			if len(v) == 0 {
				return makeErr("values", "'MCPServer' must have at least one value")
			}
			for _, v := range v {
				strVal, ok := v.(string)
				if !ok {
					return makeErr("values", "Key 'MCPServer' only supports string values when operator is 'Any' or 'NotAny'")
				}
				if strings.Contains(strVal, `"`) {
					return makeErr("values", "Key 'MCPServer' must not have a value that contains a quote")
				}
			}
		}
		if o == PredicateOperatorEmpty || o == PredicateOperatorNotEmpty {
			if len(v) > 0 {
				return makeErr("values", "Key 'MCPServer' only supports no values when operation is 'Empty' or 'NotEmpty'")
			}
		}

	case PredicateKeyRiskScore:
		if o != PredicateOperatorEqualsOrLesserThan && o != PredicateOperatorEqualsOrGreaterThan {
			return makeErr("operator", "Key 'RiskScore' only supports operators 'EqualsOrGreaterThan' and 'EqualsOrLesserThan'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'RiskScore' only supports one single value")
		}
		switch t := p.Values[0].(type) {
		case int, float64, uint64, int64:
		default:
			return makeErr("values", fmt.Sprintf("Key 'RiskScore' only supports float value. Found '%T'", t))
		}

	case PredicateKeyStatus:
		if o != PredicateOperatorEquals && o != PredicateOperatorNotEquals {
			return makeErr("operator", "Key 'Status' only supports operator 'Equals' and 'NotEquals'")
		}
		if len(p.Values) != 1 {
			return makeErr("values", "Key 'Status' only supports one single value")
		}
		if _, ok := p.Values[0].(string); !ok {
			return makeErr("values", "Key 'Status' only supports string value")
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
		if sink.Slack != nil || sink.Splunk != nil || sink.PagerDuty != nil {
			return makeErr("type", "If type is 'Email', only the email property must be set.")
		}
	case SinkTypePagerDuty:
		if sink.PagerDuty == nil {
			return makeErr("pagerDuty", "'PagerDuty' must have its configuration defined.")
		}
		if sink.Slack != nil || sink.Splunk != nil || sink.Email != nil {
			return makeErr("type", "If type is 'PageDuty', only the pagerDuty property must be set.")
		}
	case SinkTypeSlack:
		if sink.Slack == nil {
			return makeErr("slack", "'Slack' must have its configuration defined.")
		}
		if sink.PagerDuty != nil || sink.Splunk != nil || sink.Email != nil {
			return makeErr("type", "If type is 'Slack', only the slack property must be set.")
		}
	case SinkTypeSplunk:
		if sink.Splunk == nil {
			return makeErr("splunk", "'Splunk' must have its configuration defined.")
		}
		if sink.PagerDuty != nil || sink.Slack != nil || sink.Email != nil {
			return makeErr("type", "If type is 'Splunk', only the splunk property must be set.")
		}
	}

	return nil
}

// ValidateApp validates the app object
func ValidateApp(app *App) error {

	m := make(map[string]struct{}, len(app.Components))
	wgm := make(map[string]struct{}, len(app.Components))
	for i, component := range app.Components {
		if component.Name == "_default" {
			return makeErr("name", "_default is a reserved component name")
		}

		// ensure component selector type matches the app selector type
		switch app.Selector.Type {
		case AppSelectorTypeKubernetes:
			if component.Selector.Type != AppComponentSelectorTypeKubernetes {
				return makeErr(fmt.Sprintf("components/%d/selector", i), fmt.Sprintf("component '%s' selector type must be 'Kubernetes' to match the app selector type", component.Name))
			}
		}

		// ensure component names are unique
		if _, ok := m[component.Name]; ok {
			return makeErr("name", fmt.Sprintf("another component is already named '%s'", component.Name))
		}
		m[component.Name] = struct{}{}

		// ensure component selectors are unique
		wgh := WorkloadGroupHashFromSelector(&component.Selector)
		if wgh == "" {
			return makeErr(fmt.Sprintf("components/%d/selector", i), fmt.Sprintf("component '%s' has an invalid Kubernetes selector (workload group hash computation failed)", component.Name))
		}
		if _, ok := wgm[wgh]; ok {
			return makeErr(fmt.Sprintf("components/%d/selector", i), fmt.Sprintf("another component is already using the same Kubernetes selector as component '%s'", component.Name))
		}
		wgm[wgh] = struct{}{}

		// ensure Kubernetes component selectors all carry the same namespace
		if component.Selector.Type == AppComponentSelectorTypeKubernetes {
			if app.Selector.Kubernetes.KubernetesNamespace != component.Selector.Kubernetes.KubernetesNamespace {
				return makeErr(fmt.Sprintf("components/%d/selector", i), "Kubernetes component selectors must carry the same Kubernetes namespace as the Kubernetes app selector")
			}
		}
	}

	otelReceivers := map[string]struct{}{}
	for _, otelReceiver := range app.OtelReceivers {
		endpoint := otelReceiver.Endpoint

		// we should be able to split the IP:Port pair
		// NOTE: this is already being done in ValidateIPPort, but we cannot rely on this in this function
		host, portStr, err := net.SplitHostPort(endpoint)
		if err != nil {
			return makeErr("otelReceivers", fmt.Sprintf("Invalid IP:Port pair '%s': %s", endpoint, err))
		}
		if host == "" {
			host = "0.0.0.0"
		}
		if portStr == "" {
			return makeErr("otelReceivers", fmt.Sprintf("Invalid IP:Port pair '%s': port is empty", endpoint))
		}
		endpoint = net.JoinHostPort(host, portStr)

		if _, ok := otelReceivers[endpoint]; ok {
			return makeErr("otelReceivers", fmt.Sprintf("duplicate OpenTelemetry receiver endpoint '%s'", otelReceiver.Endpoint))
		}
		otelReceivers[endpoint] = struct{}{}
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

	// Duration validation is already done prior to this
	if d, _ := time.ParseDuration(agentConfig.ConfigRefreshInterval); d < 5*time.Minute {
		return makeErr("configRefreshInterval", "'ConfigRefreshInterval' cannot be lower than 5m")
	}

	if d, _ := time.ParseDuration(agentConfig.DomainReportInterval); d < 5*time.Minute {
		return makeErr("domainReportInterval", "'DomainReportInterval' cannot be lower than 5m")
	}

	if d, _ := time.ParseDuration(agentConfig.PingInterval); d < 5*time.Minute {
		return makeErr("pingInterval", "'PingInterval' cannot be lower than 5m")
	}

	if d, _ := time.ParseDuration(agentConfig.ScanInterval); d < 30*time.Second {
		return makeErr("scanInterval", "'ScanInterval' cannot be lower than 30s")
	}

	if d, _ := time.ParseDuration(agentConfig.ScanReportInterval); d < 5*time.Minute {
		return makeErr("scanReportInterval", "'ScanReportInterval' cannot be lower than 5m")
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

// ValidateRegexp validates the given input is a valid re2 regex.
func ValidateRegexp(attribute string, r string) error {

	if r == "" {
		return nil
	}

	if _, err := regexp.Compile(r); err != nil {
		return makeErr(attribute, fmt.Sprintf("Invalid regexp: %s", err))
	}

	return nil
}

// ValidateRegexps validates the given input is a valid list of re2 regex.
func ValidateRegexps(attribute string, r []string) error {

	if len(r) == 0 {
		return nil
	}

	for i, rr := range r {
		if err := ValidateRegexp(attribute, rr); err != nil {
			return makeErr(attribute, fmt.Sprintf("Invalid item %d: %s", i, err))
		}
	}

	return nil
}

// ValidateIP validates the given input is a valid IP address.
func ValidateIP(attribute string, ipStr string) error {

	if ipStr == "" {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return makeErr(attribute, fmt.Sprintf("Invalid IP address '%s'", ipStr))
	}

	return nil
}

// ValidateIPPort validate the given input is a valid IP:Port pair.
// The port must be in the range 0-65535 and the host must be a valid IP address.
// If the IP is empty, the any address (0.0.0.0) will be assumed.
// The IP must be an IP address, hostnames are not allowed.
func ValidateIPPort(attribute string, ipPort string) error {
	// we should be able to split the IP:Port pair
	host, portStr, err := net.SplitHostPort(ipPort)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("Invalid IP:Port pair '%s': %s", ipPort, err))
	}

	if host == "" {
		host = "0.0.0.0"
	}

	if portStr == "" {
		return makeErr(attribute, fmt.Sprintf("Invalid IP:Port pair '%s': port is empty", ipPort))
	}

	// ensure the port is indeed a number and is within range
	if err = ValidatePort(attribute, portStr); err != nil {
		return err
	}

	// ensure the host is indeed an IP address: hostnames are not allowed
	ip := net.ParseIP(host)
	if ip == nil {
		return makeErr(attribute, fmt.Sprintf("Invalid IP address '%s': %s", host, err))
	}

	return nil
}

// ValidatePort checks that the port is a valid number in the range 0-65535.
func ValidatePort(attribute string, portStr string) error {

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return makeErr(attribute, fmt.Sprintf("Invalid port '%s': %s", portStr, err))
	}

	if port <= 0 || port >= 65535 {
		return makeErr(attribute, fmt.Sprintf("Invalid port '%d': must be within range of 0 and 65535", port))
	}

	return nil
}

// ValidateDomain checks that string sent is actually a domain.
func ValidateDomain(attribute string, domain string) error {

	if domain == "" {
		return nil
	}

	if u, err := url.Parse(domain); err == nil && u.Scheme != "" {
		return makeErr(attribute, fmt.Sprintf("Invalid domain '%s': must not be a full URL", domain))
	}

	// @TODO: Uncomment
	// some clients are still sending IPs.
	// Since we can't rely on good citizenship, this will refuse plain
	// and simple if the domain is an IP address. However to not break
	// existing clients (the whole batch of visited URL would be refused)
	// right now there is a check in the processor to force ignore IP

	// if net.ParseIP(domain) != nil {
	// 	return makeErr(attribute, fmt.Sprintf("Invalid domain '%s': must not be an IP address", domain))
	// }

	if strings.ContainsAny(domain, "/?#") {
		return makeErr(attribute, fmt.Sprintf("Invalid domain '%s': must not contain slashes, query, or fragment", domain))
	}

	if strings.HasPrefix(domain, "www.") {
		return makeErr(attribute, fmt.Sprintf("Invalid domain '%s': must not have 'www.' prefix", domain))
	}

	// TODO: remove the localhost check when we stop reporting this
	// from acushield and webext.
	if !strings.Contains(domain, ".") && domain != "localhost" {
		return makeErr(attribute, fmt.Sprintf("Invalid domain '%s': must contain at least one dot", domain))
	}

	return nil
}

// ValidateAgentConfig validates the agent configuration object.
func ValidateOrgStorage(orgStorage *OrgStorage) error {

	byteCount := len(orgStorage.Value)
	sizeKB := float64(byteCount) / 1e3

	if sizeKB > 200 {
		return makeErr("value", "The value is limited to 200KB")
	}

	return nil
}

// ValidateIngestTrace validates an ingest trace object.
func ValidateIngestTrace(ingestTrace *IngestTrace) error {

	if len(ingestTrace.Traces) == 0 && ingestTrace.Raw == "" {
		return makeErr("spans", "You must provide either at least one trace or a raw ingestion value")
	}

	if len(ingestTrace.Traces) > 0 && ingestTrace.Raw != "" {
		return makeErr("spans", "You cannot provide both traces and a raw ingestion value")
	}

	return nil
}

// ValidateOTLPJSON validates the given input is a valid OTLP JSON string.
func ValidateOTLPJSON(attribute, otlpJSON string) error {

	if otlpJSON == "" {
		return nil
	}

	if _, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces([]byte(otlpJSON)); err != nil {
		return makeErr(attribute, fmt.Sprintf("'%s' is invalid OTLP JSON: %s", attribute, err))
	}

	return nil
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

// ValidateCron validates the expressions is a valid crontab string.
func ValidateCron(attribute string, expr string) error {

	if expr == "" {
		return nil
	}

	if _, err := cron.ParseStandard(expr); err != nil {
		return makeErr(attribute, fmt.Sprintf("'%s' is not a valid crontab expression: %s", expr, err))
	}

	return nil
}

// ValidateAIPlugin validates the AIPlugin object.
func ValidateAIPlugin(plugin *AIPlugin) error {

	switch plugin.Type {
	case AIPluginTypeIDE:
		if plugin.IDE == nil {
			return makeErr("IDE", "'IDE' must have its configuration defined.")
		}
	case AIPluginTypeWebExtension:
		if plugin.WebExtension == nil {
			return makeErr("webExtension", "'WebExtension' must have its configuration defined.")
		}

		if plugin.WebExtension.ChromeID == "" && plugin.WebExtension.EdgeID == "" && plugin.WebExtension.FirefoxID == "" {
			return makeErr("webExtension", "'WebExtension' must have at least one ID defined.")
		}
	}

	return nil
}

var validIndustries = map[string]struct{}{
	"All":                                  {},
	"Technology & software":                {},
	"Financial services & insurance":       {},
	"Healthcare & life sciences":           {},
	"Government & public sector":           {},
	"Education":                            {},
	"Legal & professional services":        {},
	"Telecommunications":                   {},
	"Media & entertainment (incl. gaming)": {},
	"Retail & e-commerce":                  {},
	"Consumer packaged goods":              {},
	"Manufacturing & industrials":          {},
	"Energy & utilities":                   {},
	"Automotive & mobility":                {},
	"Transport, logistics & supply chain":  {},
	"Travel, hospitality & leisure":        {},
	"Real estate & construction":           {},
	"Agriculture & food":                   {},
	"Advertising, marketing & agencies":    {},
	"Nonprofit & NGOs":                     {},
}

// ValidateAIDomainIndustries validates the given list of industry.
func ValidateAIDomainIndustries(attribute string, industries []string) error {

	for i, ind := range industries {
		if _, ok := validIndustries[ind]; !ok {
			return makeErr(attribute, fmt.Sprintf("'%s' (position %d) is not a valid industry", ind, i))
		}
	}

	return nil
}

// ValidateCIDRs validates the given inputs are valid lists of CIDR notations.
func ValidateCIDRs(attribute string, cidrs []string) error {

	if len(cidrs) == 0 {
		return nil
	}

	for i, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return makeErr(attribute, fmt.Sprintf("Invalid CIDR at index %d: %s", i, err))
		}
	}

	return nil
}

var (
	// valid DNS label: LDH (letters, digits, hyphen) with no leading/trailing hyphen, max 63 chars
	validHostnameLabel = `[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?`

	// for the egress policies, a valid hostname is:
	// optional leading wildcard followed immediately by a dot (*.|**.), then at least one label, no trailing dot
	validPolicyHostnameRegex = regexp.MustCompile(
		`^(?:(?:\*\*|\*)\.)?(?:` + validHostnameLabel + `\.)*` + validHostnameLabel + `$`,
	)

	// Allow a single label or multiple labels separated by dots; no trailing dot
	validOnePlusLabelsDNSNameRegex = regexp.MustCompile(`^` + validHostnameLabel + `(?:\.` + validHostnameLabel + `)*$`)
)

// ValidatePolicyHostnames validates the given hostnames to be valid strings for egress policy usage.
func ValidatePolicyHostnames(attribute string, hostnames []string) error {

	if len(hostnames) == 0 {
		return nil
	}

	for i, hostname := range hostnames {
		if hostname == "" {
			return makeErr(attribute, fmt.Sprintf("Hostname at index %d is empty", i))
		}

		if !validPolicyHostnameRegex.MatchString(hostname) {
			return makeErr(attribute, fmt.Sprintf("Hostname at index %d is an invalid policy hostname: it can have an optional leading wildcard (*.|**.), and must consist of at least one label.", i))
		}
	}

	return nil
}

// ValidateDNSName validates the given DNS name to be a valid string for a typical DNS name excluding a dotted end.
func ValidateDNSName(attribute, dnsName string) error {

	if dnsName == "" {
		return nil
	}

	if !validOnePlusLabelsDNSNameRegex.MatchString(dnsName) {
		return makeErr(attribute, fmt.Sprintf("DNS name '%s' is an invalid DNS name: it must consist of at least one label.", dnsName))
	}

	return nil
}

// ValidateDNSNames validates the given DNS names to be valid strings for a typical DNS name excluding a dotted end.
func ValidateDNSNames(attribute string, dnsNames []string) error {

	if len(dnsNames) == 0 {
		return nil
	}

	for i, dnsName := range dnsNames {
		if dnsName == "" {
			return makeErr(attribute, fmt.Sprintf("DNS name at index %d is empty", i))
		}

		if !validOnePlusLabelsDNSNameRegex.MatchString(dnsName) {
			return makeErr(attribute, fmt.Sprintf("DNS name at index %d is an invalid DNS name: it must consist of at least one label.", i))
		}
	}

	return nil
}

// ValidateAppGraphQuery validates the app graph query object.
func ValidateAppGraphQuery(appGraphQuery *AppGraphQuery) error {

	if appGraphQuery.AppGraphKind != AppGraphQueryAppGraphKindAll && len(appGraphQuery.WorkloadGroupSetHashes) > 0 {
		return makeErr("workloadGroupSetHashes", "'WorkloadGroupSetHashes' cannot be set when 'AppGraphKind' is set.")
	}

	return nil
}

// ValidateAppComponentReferences validates the references to app components.
func ValidateAppComponentReferences(attribute string, references []string) error {

	if len(references) == 0 {
		return nil
	}

	m := map[string]struct{}{}
	for _, ref := range references {
		if ref == "" {
			return makeErr(attribute, "Reference cannot be empty")
		}
		if _, ok := m[ref]; ok {
			return makeErr(attribute, fmt.Sprintf("Duplicate reference found: '%s'", ref))
		}
		m[ref] = struct{}{}

		// an app component reference can only have one slash, or no slash when referring to all components
		// and obviously after the split they cannot be empty
		parts := strings.Split(ref, "/")
		if len(parts) > 2 {
			return makeErr(attribute, fmt.Sprintf("Invalid reference '%s': can only contain one slash", ref))
		}
		if len(parts) == 2 {
			if parts[0] == "" {
				return makeErr(attribute, fmt.Sprintf("Invalid reference '%s': app name cannot be empty", ref))
			}
			if parts[1] == "" {
				return makeErr(attribute, fmt.Sprintf("Invalid reference '%s': component name cannot be empty", ref))
			}
		}
		if len(parts) == 1 {
			if parts[0] == "" {
				return makeErr(attribute, "Invalid reference: cannot be empty")
			}
		}
	}

	return nil
}

// ValidateAppSelector validates the app selector object.
func ValidateAppSelector(appSelector *AppSelector) error {

	switch appSelector.Type {
	case AppSelectorTypeKubernetes:
		if appSelector.Kubernetes == nil {
			return makeErr("kubernetes", "Kubernetes app selector must be defined if app selector 'type' is set to 'Kubernetes'.")
		}
		return nil
	default:
		return makeErr("type", fmt.Sprintf("Unknown app selector type '%s'.", appSelector.Type))
	}
}

// ValidateAppComponentSelector validates the app component selector object.
func ValidateAppComponentSelector(appComponentSelector *AppComponentSelector) error {

	switch appComponentSelector.Type {
	case AppComponentSelectorTypeKubernetes:
		if appComponentSelector.Kubernetes == nil {
			return makeErr("kubernetes", "Kubernetes app component selector must be defined if app component selector 'type' is set to 'Kubernetes'.")
		}
		return nil
	default:
		return makeErr("type", fmt.Sprintf("Unknown app component selector type '%s'.", appComponentSelector.Type))
	}
}

// ValidateKubernetesWorkloadGroupSelector validates the Kubernetes workload group selector object.
func ValidateKubernetesWorkloadGroupSelector(kubernetesSelector *KubernetesWorkloadGroupSelector) error {

	switch kubernetesSelector.Type {
	case KubernetesWorkloadGroupSelectorTypePod:
		return nil
	case KubernetesWorkloadGroupSelectorTypeDeployment:
		return nil
	case KubernetesWorkloadGroupSelectorTypeStatefulSet:
		return nil
	case KubernetesWorkloadGroupSelectorTypeJob:
		return nil
	case KubernetesWorkloadGroupSelectorTypeCronJob:
		return nil
	case KubernetesWorkloadGroupSelectorTypeDaemonSet:
		return nil
	case KubernetesWorkloadGroupSelectorTypeCustom:
		if kubernetesSelector.Custom == nil {
			return makeErr("custom", "Custom Kubernetes workload group selector must be defined if 'type' is set to 'Custom'.")
		}
		return nil
	default:
		return makeErr("type", fmt.Sprintf("Unknown Kubernetes workload group selector type '%s'.", kubernetesSelector.Type))
	}
}

// ValidateAppReport validates the app report object.
func ValidateAppReport(appReport *AppReport) error {
	if len(appReport.ConnectionReports) == 0 && len(appReport.DNSReports) == 0 {
		return makeErr("connectionReports", "At least one connection report or DNS report must be provided")
	}
	return nil
}

// ValidateDNSReport validates the DNS report object.
func ValidateDNSReport(dnsReport *DNSReport) error {
	if dnsReport.Action == DNSReportActionAllow && len(dnsReport.IPAddresses) == 0 && len(dnsReport.CNAMEs) == 0 {
		return makeErr("ipAddresses", "At least one IP address or one CNAME must be provided when action is 'Allow'")
	}
	return nil
}

// ValidateEgressPolicy validates the egress policy object.
func ValidateEgressPolicy(egressPolicy *EgressPolicy) error {
	if len(egressPolicy.Rules) == 0 && len(egressPolicy.ACLs) == 0 {
		return makeErr("rules", "At least one rule or ACL must be provided")
	}
	return nil
}

// ValidateEgressPolicyACL validates the egress policy ACL object.
func ValidateEgressPolicyACL(egressPolicyACL *EgressPolicyACL) error {
	if len(egressPolicyACL.Hostnames) == 0 && len(egressPolicyACL.IPRanges) == 0 {
		return makeErr("hostnames", "At least one hostname or IP range must be provided")
	}
	return nil
}

// ValidateEgressPolicyRule validates the egress policy rule object.
func ValidateEgressPolicyRule(egressPolicyRule *EgressPolicyRule) error {

	if len(egressPolicyRule.AppComponents) == 0 && len(egressPolicyRule.Providers) == 0 {
		return makeErr("appComponents", "At least one app component or provider must be provided")
	}
	if len(egressPolicyRule.AppComponents) > 0 && len(egressPolicyRule.Providers) > 0 {
		return makeErr("appComponents", "You cannot provide both app components and providers")
	}

	switch egressPolicyRule.Mode {
	case EgressPolicyRuleModeProxy:
		if egressPolicyRule.ProxyAction != EgressPolicyRuleProxyActionAllow && egressPolicyRule.ProxyAction != EgressPolicyRuleProxyActionDeny {
			return makeErr("proxyAction", "When 'Mode' is set to 'Proxy', 'ProxyAction' must be either 'Allow' or 'Deny'")
		}
	default:
		if egressPolicyRule.ProxyAction != EgressPolicyRuleProxyActionNotApplicable && egressPolicyRule.ProxyAction != "" {
			return makeErr("proxyAction", "When 'Mode' is not set to 'Proxy', 'ProxyAction' must be 'NotApplicable'")
		}
	}

	return nil
}

// ValidateIngressACL validates the ingress ACL object.
func ValidateIngressACL(ingressACL *IngressACL) error {
	// TODO: looking at this right now, I don't know anymore why I thought that this needs a custom validation
	return nil
}

// ValidateIngressListener validates the ingress listener object.
func ValidateIngressListener(ingressListener *IngressListener) error {
	switch ingressListener.Mode {
	case IngressListenerModePassthrough:
		// nothing to do for passthrough
		return nil
	case IngressListenerModeProxy:
		if ingressListener.Proxy == nil {
			return makeErr("proxy", "'Proxy' must be defined if 'Mode' is set to 'Proxy'.")
		}
	default:
		return makeErr("mode", fmt.Sprintf("Unknown ingress listener mode '%s'.", ingressListener.Mode))
	}
	return nil
}

// ValidateIngressListeners validates a list of ingress listeners.
func ValidateIngressListeners(attribute string, ingressListeners []*IngressListener) error {

	if len(ingressListeners) == 0 {
		return nil
	}

	m := map[int]struct{}{}
	for _, listener := range ingressListeners {
		if _, ok := m[listener.Port]; ok {
			return makeErr(attribute, fmt.Sprintf("another listener is already using port '%d'", listener.Port))
		}
		m[listener.Port] = struct{}{}
	}
	return nil
}

// ValidateIngressPolicy validates the ingress policy object.
func ValidateIngressPolicy(ingressPolicy *IngressPolicy) error {
	// TODO: looking at this right now, I don't know anymore why I thought that this needs a custom validation
	return nil
}

// ValidateIngressPolicyRule validates the ingress policy rule object.
func ValidateIngressPolicyRule(ingressPolicyRule *IngressPolicyRule) error {
	if len(ingressPolicyRule.AppComponents) == 0 && len(ingressPolicyRule.IPRanges) == 0 {
		return makeErr("appComponents", "At least one app component or IP range must be provided")
	}
	if len(ingressPolicyRule.AppComponents) > 0 && len(ingressPolicyRule.IPRanges) > 0 {
		return makeErr("appComponents", "You cannot provide both app components and IP ranges")
	}
	return nil
}

// ValidateIngressProxyConfig validates the ingress proxy configuration object.
func ValidateIngressProxyConfig(ingressProxyConfig *IngressProxyConfig) error {

	// TODO: keeping this validation here until we bring this back in which case it will be needed again
	// if (ingressProxyConfig.ListenTLSKey == "" && ingressProxyConfig.ListenTLSCert != "") ||
	// 	(ingressProxyConfig.ListenTLSKey != "" && ingressProxyConfig.ListenTLSCert == "") {
	// 	return makeErr("listenTLSCert", "'ListenTLSCert' and 'ListenTLSKey' must both be defined or both be empty.")
	// }
	return nil
}

// ValidateOrgSetting validates the orgsetting object
func ValidateOrgSetting(o *OrgSettings) error {

	if strings.ContainsAny(o.ConsentMessage, "`") {
		return makeErr("consentMessage", "The consent message must not contain any backtick ('`')")
	}

	return nil
}

// ValidateRESTName validates the rest name is a known identity
func ValidateRESTName(attribute, restName string) error {

	identifiable := Manager().IdentifiableFromString(restName)

	if identifiable == nil {
		identifiable = a3sapi.Manager().IdentifiableFromString(restName)
		if identifiable == nil {
			return makeErr(attribute, fmt.Sprintf("No known identifiables match the REST name %s", restName))
		}
	}

	if _, ok := identifiable.(elemental.Validatable); !ok {
		return makeErr(attribute, fmt.Sprintf("identifiable %s does not have a validate capability", restName))
	}

	return nil
}

func makeErr(attribute string, message string) elemental.Error {

	err := elemental.NewError(
		"Validation Error",
		message,
		"api",
		http.StatusUnprocessableEntity,
	)

	if attribute != "" {
		err.Data = map[string]any{"attribute": attribute}
	}

	return err
}

// validateToolMisalignmentExploit - validate that Tool misalignement exploit is paired
// with some tool use names.
func ValidateToolMisalignmentExploit(moderation *Moderation, moderationIndex int) error {

	const exploitValueIntentToolMismatch = "intent_tool_mismatch"

	allowed := map[PredicateOperatorValue]struct{}{
		PredicateOperatorAny:    {},
		PredicateOperatorEquals: {},
	}

	hasIntentToolMismatch := false
	hasToolUsesWithNames := false
	exploitIndex := -1

	for i, p := range moderation.Predicates {
		if _, ok := allowed[p.Operator]; !ok {
			continue
		}

		switch p.Key {
		case "Exploits":
			for _, v := range p.Values {
				if v == exploitValueIntentToolMismatch {
					hasIntentToolMismatch = true
					exploitIndex = i
					break
				}
			}

		case "ToolUses":
			if len(p.Values) > 0 {
				hasToolUsesWithNames = true
			}
		}

		if hasIntentToolMismatch && hasToolUsesWithNames {
			return nil
		}
	}

	if hasIntentToolMismatch && !hasToolUsesWithNames {
		return makeErr(
			fmt.Sprintf("moderation/%d/predicates/%d", moderationIndex, exploitIndex),
			fmt.Sprintf(
				"Tool misalignment exploit need to be paired with Tool Use with '%s' or '%s' operator",
				PredicateOperatorAny,
				PredicateOperatorEquals,
			),
		)
	}

	return nil
}
