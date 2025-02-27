// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// ProviderRetentionPolicySubscriptionTypeValue represents the possible values for attribute "subscriptionType".
type ProviderRetentionPolicySubscriptionTypeValue string

const (
	// ProviderRetentionPolicySubscriptionTypeEnterprise represents the value Enterprise.
	ProviderRetentionPolicySubscriptionTypeEnterprise ProviderRetentionPolicySubscriptionTypeValue = "Enterprise"

	// ProviderRetentionPolicySubscriptionTypeFree represents the value Free.
	ProviderRetentionPolicySubscriptionTypeFree ProviderRetentionPolicySubscriptionTypeValue = "Free"

	// ProviderRetentionPolicySubscriptionTypePaid represents the value Paid.
	ProviderRetentionPolicySubscriptionTypePaid ProviderRetentionPolicySubscriptionTypeValue = "Paid"
)

// ProviderRetentionPolicy represents the model of a providerretentionpolicy
type ProviderRetentionPolicy struct {
	// Description of the data retention policy for the subscription type.
	Description string `json:"description,omitempty" msgpack:"description,omitempty" bson:"description,omitempty" mapstructure:"description,omitempty"`

	// The duration of time the data retention policy applies to the subscription type.
	Duration string `json:"duration,omitempty" msgpack:"duration,omitempty" bson:"duration,omitempty" mapstructure:"duration,omitempty"`

	// The type of subscription for which the data retention policy needs to be
	// defined.
	SubscriptionType ProviderRetentionPolicySubscriptionTypeValue `json:"subscriptionType,omitempty" msgpack:"subscriptionType,omitempty" bson:"subscriptiontype,omitempty" mapstructure:"subscriptionType,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewProviderRetentionPolicy returns a new *ProviderRetentionPolicy
func NewProviderRetentionPolicy() *ProviderRetentionPolicy {

	return &ProviderRetentionPolicy{
		ModelVersion:     1,
		SubscriptionType: ProviderRetentionPolicySubscriptionTypeFree,
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *ProviderRetentionPolicy) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesProviderRetentionPolicy{}

	s.Description = o.Description
	s.Duration = o.Duration
	s.SubscriptionType = o.SubscriptionType

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *ProviderRetentionPolicy) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesProviderRetentionPolicy{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.Description = s.Description
	o.Duration = s.Duration
	o.SubscriptionType = s.SubscriptionType

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *ProviderRetentionPolicy) BleveType() string {

	return "providerretentionpolicy"
}

// DeepCopy returns a deep copy if the ProviderRetentionPolicy.
func (o *ProviderRetentionPolicy) DeepCopy() *ProviderRetentionPolicy {

	if o == nil {
		return nil
	}

	out := &ProviderRetentionPolicy{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *ProviderRetentionPolicy.
func (o *ProviderRetentionPolicy) DeepCopyInto(out *ProviderRetentionPolicy) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy ProviderRetentionPolicy: %s", err))
	}

	*out = *target.(*ProviderRetentionPolicy)
}

// Validate valides the current information stored into the structure.
func (o *ProviderRetentionPolicy) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateStringInList("subscriptionType", string(o.SubscriptionType), []string{"Enterprise", "Paid", "Free"}, false); err != nil {
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
func (*ProviderRetentionPolicy) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := ProviderRetentionPolicyAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return ProviderRetentionPolicyLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*ProviderRetentionPolicy) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return ProviderRetentionPolicyAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *ProviderRetentionPolicy) ValueForAttribute(name string) any {

	switch name {
	case "description":
		return o.Description
	case "duration":
		return o.Duration
	case "subscriptionType":
		return o.SubscriptionType
	}

	return nil
}

// ProviderRetentionPolicyAttributesMap represents the map of attribute for ProviderRetentionPolicy.
var ProviderRetentionPolicyAttributesMap = map[string]elemental.AttributeSpecification{
	"Description": {
		AllowedChoices: []string{},
		BSONFieldName:  "description",
		ConvertedName:  "Description",
		Description:    `Description of the data retention policy for the subscription type.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"Duration": {
		AllowedChoices: []string{},
		BSONFieldName:  "duration",
		ConvertedName:  "Duration",
		Description:    `The duration of time the data retention policy applies to the subscription type.`,
		Exposed:        true,
		Name:           "duration",
		Stored:         true,
		Type:           "string",
	},
	"SubscriptionType": {
		AllowedChoices: []string{"Enterprise", "Paid", "Free"},
		BSONFieldName:  "subscriptiontype",
		ConvertedName:  "SubscriptionType",
		DefaultValue:   ProviderRetentionPolicySubscriptionTypeFree,
		Description: `The type of subscription for which the data retention policy needs to be
defined.`,
		Exposed: true,
		Name:    "subscriptionType",
		Stored:  true,
		Type:    "enum",
	},
}

// ProviderRetentionPolicyLowerCaseAttributesMap represents the map of attribute for ProviderRetentionPolicy.
var ProviderRetentionPolicyLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"description": {
		AllowedChoices: []string{},
		BSONFieldName:  "description",
		ConvertedName:  "Description",
		Description:    `Description of the data retention policy for the subscription type.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"duration": {
		AllowedChoices: []string{},
		BSONFieldName:  "duration",
		ConvertedName:  "Duration",
		Description:    `The duration of time the data retention policy applies to the subscription type.`,
		Exposed:        true,
		Name:           "duration",
		Stored:         true,
		Type:           "string",
	},
	"subscriptiontype": {
		AllowedChoices: []string{"Enterprise", "Paid", "Free"},
		BSONFieldName:  "subscriptiontype",
		ConvertedName:  "SubscriptionType",
		DefaultValue:   ProviderRetentionPolicySubscriptionTypeFree,
		Description: `The type of subscription for which the data retention policy needs to be
defined.`,
		Exposed: true,
		Name:    "subscriptionType",
		Stored:  true,
		Type:    "enum",
	},
}

type mongoAttributesProviderRetentionPolicy struct {
	Description      string                                       `bson:"description,omitempty"`
	Duration         string                                       `bson:"duration,omitempty"`
	SubscriptionType ProviderRetentionPolicySubscriptionTypeValue `bson:"subscriptiontype,omitempty"`
}
