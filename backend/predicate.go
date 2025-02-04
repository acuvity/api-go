// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// PredicateKeyValue represents the possible values for attribute "key".
type PredicateKeyValue string

const (
	// PredicateKeyCategories represents the value Categories.
	PredicateKeyCategories PredicateKeyValue = "Categories"

	// PredicateKeyConfidentiality represents the value Confidentiality.
	PredicateKeyConfidentiality PredicateKeyValue = "Confidentiality"

	// PredicateKeyExploits represents the value Exploits.
	PredicateKeyExploits PredicateKeyValue = "Exploits"

	// PredicateKeyKeywords represents the value Keywords.
	PredicateKeyKeywords PredicateKeyValue = "Keywords"

	// PredicateKeyLanguages represents the value Languages.
	PredicateKeyLanguages PredicateKeyValue = "Languages"

	// PredicateKeyModality represents the value Modality.
	PredicateKeyModality PredicateKeyValue = "Modality"

	// PredicateKeyModel represents the value Model.
	PredicateKeyModel PredicateKeyValue = "Model"

	// PredicateKeyPIIs represents the value PIIs.
	PredicateKeyPIIs PredicateKeyValue = "PIIs"

	// PredicateKeyPlugin represents the value Plugin.
	PredicateKeyPlugin PredicateKeyValue = "Plugin"

	// PredicateKeyProvider represents the value Provider.
	PredicateKeyProvider PredicateKeyValue = "Provider"

	// PredicateKeyRelevance represents the value Relevance.
	PredicateKeyRelevance PredicateKeyValue = "Relevance"

	// PredicateKeySecrets represents the value Secrets.
	PredicateKeySecrets PredicateKeyValue = "Secrets"

	// PredicateKeySize represents the value Size.
	PredicateKeySize PredicateKeyValue = "Size"

	// PredicateKeyTeam represents the value Team.
	PredicateKeyTeam PredicateKeyValue = "Team"

	// PredicateKeyTools represents the value Tools.
	PredicateKeyTools PredicateKeyValue = "Tools"

	// PredicateKeyTopics represents the value Topics.
	PredicateKeyTopics PredicateKeyValue = "Topics"

	// PredicateKeyWorkspace represents the value Workspace.
	PredicateKeyWorkspace PredicateKeyValue = "Workspace"
)

// PredicateOperatorValue represents the possible values for attribute "operator".
type PredicateOperatorValue string

const (
	// PredicateOperatorAll represents the value All.
	PredicateOperatorAll PredicateOperatorValue = "All"

	// PredicateOperatorAny represents the value Any.
	PredicateOperatorAny PredicateOperatorValue = "Any"

	// PredicateOperatorEmpty represents the value Empty.
	PredicateOperatorEmpty PredicateOperatorValue = "Empty"

	// PredicateOperatorEquals represents the value Equals.
	PredicateOperatorEquals PredicateOperatorValue = "Equals"

	// PredicateOperatorEqualsOrGreaterThan represents the value EqualsOrGreaterThan.
	PredicateOperatorEqualsOrGreaterThan PredicateOperatorValue = "EqualsOrGreaterThan"

	// PredicateOperatorEqualsOrLesserThan represents the value EqualsOrLesserThan.
	PredicateOperatorEqualsOrLesserThan PredicateOperatorValue = "EqualsOrLesserThan"

	// PredicateOperatorNotAny represents the value NotAny.
	PredicateOperatorNotAny PredicateOperatorValue = "NotAny"

	// PredicateOperatorNotEmpty represents the value NotEmpty.
	PredicateOperatorNotEmpty PredicateOperatorValue = "NotEmpty"

	// PredicateOperatorNotEquals represents the value NotEquals.
	PredicateOperatorNotEquals PredicateOperatorValue = "NotEquals"
)

// Predicate represents the model of a predicate
type Predicate struct {
	// The key of the predicate.
	Key PredicateKeyValue `json:"key" msgpack:"key" bson:"key" mapstructure:"key,omitempty"`

	// The operator of the predicate.
	Operator PredicateOperatorValue `json:"operator" msgpack:"operator" bson:"operator" mapstructure:"operator,omitempty"`

	// The values of the predicate.
	Values []any `json:"values" msgpack:"values" bson:"values" mapstructure:"values,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewPredicate returns a new *Predicate
func NewPredicate() *Predicate {

	return &Predicate{
		ModelVersion: 1,
		Values:       []any{},
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Predicate) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesPredicate{}

	s.Key = o.Key
	s.Operator = o.Operator
	s.Values = o.Values

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Predicate) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesPredicate{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.Key = s.Key
	o.Operator = s.Operator
	o.Values = s.Values

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *Predicate) BleveType() string {

	return "predicate"
}

// DeepCopy returns a deep copy if the Predicate.
func (o *Predicate) DeepCopy() *Predicate {

	if o == nil {
		return nil
	}

	out := &Predicate{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Predicate.
func (o *Predicate) DeepCopyInto(out *Predicate) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Predicate: %s", err))
	}

	*out = *target.(*Predicate)
}

// Validate valides the current information stored into the structure.
func (o *Predicate) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("key", string(o.Key)); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateStringInList("key", string(o.Key), []string{"Categories", "Confidentiality", "Exploits", "Keywords", "Languages", "Modality", "Model", "PIIs", "Plugin", "Provider", "Relevance", "Secrets", "Size", "Team", "Tools", "Topics", "Workspace"}, false); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("operator", string(o.Operator)); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateStringInList("operator", string(o.Operator), []string{"All", "Any", "Empty", "Equals", "EqualsOrGreaterThan", "EqualsOrLesserThan", "NotAny", "NotEmpty", "NotEquals"}, false); err != nil {
		errors = errors.Append(err)
	}

	// Custom object validation.
	if err := ValidatePredicate(o); err != nil {
		errors = errors.Append(err)
	}

	if len(requiredErrors) > 0 {
		return requiredErrors
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// SpecificationForAttribute returns the AttributeSpecification for the given attribute name key.
func (*Predicate) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := PredicateAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return PredicateLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Predicate) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return PredicateAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Predicate) ValueForAttribute(name string) any {

	switch name {
	case "key":
		return o.Key
	case "operator":
		return o.Operator
	case "values":
		return o.Values
	}

	return nil
}

// PredicateAttributesMap represents the map of attribute for Predicate.
var PredicateAttributesMap = map[string]elemental.AttributeSpecification{
	"Key": {
		AllowedChoices: []string{"Categories", "Confidentiality", "Exploits", "Keywords", "Languages", "Modality", "Model", "PIIs", "Plugin", "Provider", "Relevance", "Secrets", "Size", "Team", "Tools", "Topics", "Workspace"},
		BSONFieldName:  "key",
		ConvertedName:  "Key",
		Description:    `The key of the predicate.`,
		Exposed:        true,
		Name:           "key",
		Required:       true,
		Stored:         true,
		Type:           "enum",
	},
	"Operator": {
		AllowedChoices: []string{"All", "Any", "Empty", "Equals", "EqualsOrGreaterThan", "EqualsOrLesserThan", "NotAny", "NotEmpty", "NotEquals"},
		BSONFieldName:  "operator",
		ConvertedName:  "Operator",
		Description:    `The operator of the predicate.`,
		Exposed:        true,
		Name:           "operator",
		Required:       true,
		Stored:         true,
		Type:           "enum",
	},
	"Values": {
		AllowedChoices: []string{},
		BSONFieldName:  "values",
		ConvertedName:  "Values",
		Description:    `The values of the predicate.`,
		Exposed:        true,
		Name:           "values",
		Stored:         true,
		SubType:        "[]any",
		Type:           "external",
	},
}

// PredicateLowerCaseAttributesMap represents the map of attribute for Predicate.
var PredicateLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"key": {
		AllowedChoices: []string{"Categories", "Confidentiality", "Exploits", "Keywords", "Languages", "Modality", "Model", "PIIs", "Plugin", "Provider", "Relevance", "Secrets", "Size", "Team", "Tools", "Topics", "Workspace"},
		BSONFieldName:  "key",
		ConvertedName:  "Key",
		Description:    `The key of the predicate.`,
		Exposed:        true,
		Name:           "key",
		Required:       true,
		Stored:         true,
		Type:           "enum",
	},
	"operator": {
		AllowedChoices: []string{"All", "Any", "Empty", "Equals", "EqualsOrGreaterThan", "EqualsOrLesserThan", "NotAny", "NotEmpty", "NotEquals"},
		BSONFieldName:  "operator",
		ConvertedName:  "Operator",
		Description:    `The operator of the predicate.`,
		Exposed:        true,
		Name:           "operator",
		Required:       true,
		Stored:         true,
		Type:           "enum",
	},
	"values": {
		AllowedChoices: []string{},
		BSONFieldName:  "values",
		ConvertedName:  "Values",
		Description:    `The values of the predicate.`,
		Exposed:        true,
		Name:           "values",
		Stored:         true,
		SubType:        "[]any",
		Type:           "external",
	},
}

type mongoAttributesPredicate struct {
	Key      PredicateKeyValue      `bson:"key"`
	Operator PredicateOperatorValue `bson:"operator"`
	Values   []any                  `bson:"values"`
}
