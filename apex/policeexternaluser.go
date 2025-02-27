// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// PoliceExternalUser represents the model of a policeexternaluser
type PoliceExternalUser struct {
	// List of claims extracted from the user query.
	Claims []string `json:"claims,omitempty" msgpack:"claims,omitempty" bson:"-" mapstructure:"claims,omitempty"`

	// The name of the external user.
	Name string `json:"name,omitempty" msgpack:"name,omitempty" bson:"-" mapstructure:"name,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewPoliceExternalUser returns a new *PoliceExternalUser
func NewPoliceExternalUser() *PoliceExternalUser {

	return &PoliceExternalUser{
		ModelVersion: 1,
		Claims:       []string{},
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *PoliceExternalUser) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesPoliceExternalUser{}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *PoliceExternalUser) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesPoliceExternalUser{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *PoliceExternalUser) BleveType() string {

	return "policeexternaluser"
}

// DeepCopy returns a deep copy if the PoliceExternalUser.
func (o *PoliceExternalUser) DeepCopy() *PoliceExternalUser {

	if o == nil {
		return nil
	}

	out := &PoliceExternalUser{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *PoliceExternalUser.
func (o *PoliceExternalUser) DeepCopyInto(out *PoliceExternalUser) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy PoliceExternalUser: %s", err))
	}

	*out = *target.(*PoliceExternalUser)
}

// Validate valides the current information stored into the structure.
func (o *PoliceExternalUser) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredExternal("claims", o.Claims); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidateNonEmptyList("claims", o.Claims); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("name", o.Name); err != nil {
		requiredErrors = requiredErrors.Append(err)
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
func (*PoliceExternalUser) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := PoliceExternalUserAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return PoliceExternalUserLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*PoliceExternalUser) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return PoliceExternalUserAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *PoliceExternalUser) ValueForAttribute(name string) any {

	switch name {
	case "claims":
		return o.Claims
	case "name":
		return o.Name
	}

	return nil
}

// PoliceExternalUserAttributesMap represents the map of attribute for PoliceExternalUser.
var PoliceExternalUserAttributesMap = map[string]elemental.AttributeSpecification{
	"Claims": {
		AllowedChoices: []string{},
		ConvertedName:  "Claims",
		Description:    `List of claims extracted from the user query.`,
		Exposed:        true,
		Name:           "claims",
		Required:       true,
		SubType:        "string",
		Type:           "list",
	},
	"Name": {
		AllowedChoices: []string{},
		ConvertedName:  "Name",
		Description:    `The name of the external user.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Type:           "string",
	},
}

// PoliceExternalUserLowerCaseAttributesMap represents the map of attribute for PoliceExternalUser.
var PoliceExternalUserLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"claims": {
		AllowedChoices: []string{},
		ConvertedName:  "Claims",
		Description:    `List of claims extracted from the user query.`,
		Exposed:        true,
		Name:           "claims",
		Required:       true,
		SubType:        "string",
		Type:           "list",
	},
	"name": {
		AllowedChoices: []string{},
		ConvertedName:  "Name",
		Description:    `The name of the external user.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Type:           "string",
	},
}

type mongoAttributesPoliceExternalUser struct {
}
