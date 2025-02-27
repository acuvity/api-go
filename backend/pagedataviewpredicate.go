// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// PageDataViewPredicateOperatorValue represents the possible values for attribute "operator".
type PageDataViewPredicateOperatorValue string

const (
	// PageDataViewPredicateOperatorAll represents the value All.
	PageDataViewPredicateOperatorAll PageDataViewPredicateOperatorValue = "All"

	// PageDataViewPredicateOperatorAny represents the value Any.
	PageDataViewPredicateOperatorAny PageDataViewPredicateOperatorValue = "Any"

	// PageDataViewPredicateOperatorEmpty represents the value Empty.
	PageDataViewPredicateOperatorEmpty PageDataViewPredicateOperatorValue = "Empty"

	// PageDataViewPredicateOperatorEquals represents the value Equals.
	PageDataViewPredicateOperatorEquals PageDataViewPredicateOperatorValue = "Equals"

	// PageDataViewPredicateOperatorEqualsOrGreaterThan represents the value EqualsOrGreaterThan.
	PageDataViewPredicateOperatorEqualsOrGreaterThan PageDataViewPredicateOperatorValue = "EqualsOrGreaterThan"

	// PageDataViewPredicateOperatorEqualsOrLesserThan represents the value EqualsOrLesserThan.
	PageDataViewPredicateOperatorEqualsOrLesserThan PageDataViewPredicateOperatorValue = "EqualsOrLesserThan"

	// PageDataViewPredicateOperatorNotAny represents the value NotAny.
	PageDataViewPredicateOperatorNotAny PageDataViewPredicateOperatorValue = "NotAny"

	// PageDataViewPredicateOperatorNotEmpty represents the value NotEmpty.
	PageDataViewPredicateOperatorNotEmpty PageDataViewPredicateOperatorValue = "NotEmpty"

	// PageDataViewPredicateOperatorNotEquals represents the value NotEquals.
	PageDataViewPredicateOperatorNotEquals PageDataViewPredicateOperatorValue = "NotEquals"
)

// PageDataViewPredicate represents the model of a pagedataviewpredicate
type PageDataViewPredicate struct {
	// The key of the page data view predicate.
	Key string `json:"key" msgpack:"key" bson:"key" mapstructure:"key,omitempty"`

	// The operator of the page data view predicate.
	Operator PageDataViewPredicateOperatorValue `json:"operator" msgpack:"operator" bson:"operator" mapstructure:"operator,omitempty"`

	// The values of the predicate.
	Values []any `json:"values" msgpack:"values" bson:"values" mapstructure:"values,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewPageDataViewPredicate returns a new *PageDataViewPredicate
func NewPageDataViewPredicate() *PageDataViewPredicate {

	return &PageDataViewPredicate{
		ModelVersion: 1,
		Values:       []any{},
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *PageDataViewPredicate) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesPageDataViewPredicate{}

	s.Key = o.Key
	s.Operator = o.Operator
	s.Values = o.Values

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *PageDataViewPredicate) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesPageDataViewPredicate{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.Key = s.Key
	o.Operator = s.Operator
	o.Values = s.Values

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *PageDataViewPredicate) BleveType() string {

	return "pagedataviewpredicate"
}

// DeepCopy returns a deep copy if the PageDataViewPredicate.
func (o *PageDataViewPredicate) DeepCopy() *PageDataViewPredicate {

	if o == nil {
		return nil
	}

	out := &PageDataViewPredicate{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *PageDataViewPredicate.
func (o *PageDataViewPredicate) DeepCopyInto(out *PageDataViewPredicate) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy PageDataViewPredicate: %s", err))
	}

	*out = *target.(*PageDataViewPredicate)
}

// Validate valides the current information stored into the structure.
func (o *PageDataViewPredicate) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("key", o.Key); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateRequiredString("operator", string(o.Operator)); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateStringInList("operator", string(o.Operator), []string{"All", "Any", "Empty", "Equals", "EqualsOrGreaterThan", "EqualsOrLesserThan", "NotAny", "NotEmpty", "NotEquals"}, false); err != nil {
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
func (*PageDataViewPredicate) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := PageDataViewPredicateAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return PageDataViewPredicateLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*PageDataViewPredicate) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return PageDataViewPredicateAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *PageDataViewPredicate) ValueForAttribute(name string) any {

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

// PageDataViewPredicateAttributesMap represents the map of attribute for PageDataViewPredicate.
var PageDataViewPredicateAttributesMap = map[string]elemental.AttributeSpecification{
	"Key": {
		AllowedChoices: []string{},
		BSONFieldName:  "key",
		ConvertedName:  "Key",
		Description:    `The key of the page data view predicate.`,
		Exposed:        true,
		Name:           "key",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"Operator": {
		AllowedChoices: []string{"All", "Any", "Empty", "Equals", "EqualsOrGreaterThan", "EqualsOrLesserThan", "NotAny", "NotEmpty", "NotEquals"},
		BSONFieldName:  "operator",
		ConvertedName:  "Operator",
		Description:    `The operator of the page data view predicate.`,
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

// PageDataViewPredicateLowerCaseAttributesMap represents the map of attribute for PageDataViewPredicate.
var PageDataViewPredicateLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"key": {
		AllowedChoices: []string{},
		BSONFieldName:  "key",
		ConvertedName:  "Key",
		Description:    `The key of the page data view predicate.`,
		Exposed:        true,
		Name:           "key",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"operator": {
		AllowedChoices: []string{"All", "Any", "Empty", "Equals", "EqualsOrGreaterThan", "EqualsOrLesserThan", "NotAny", "NotEmpty", "NotEquals"},
		BSONFieldName:  "operator",
		ConvertedName:  "Operator",
		Description:    `The operator of the page data view predicate.`,
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

type mongoAttributesPageDataViewPredicate struct {
	Key      string                             `bson:"key"`
	Operator PageDataViewPredicateOperatorValue `bson:"operator"`
	Values   []any                              `bson:"values"`
}
