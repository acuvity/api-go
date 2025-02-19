// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// Detector represents the model of a detector
type Detector struct {
	// The description of the detection.
	Description string `json:"description" msgpack:"description" bson:"-" mapstructure:"description,omitempty"`

	// The group the detection belongs to.
	Group string `json:"group" msgpack:"group" bson:"-" mapstructure:"group,omitempty"`

	// The label returned by the model.
	Label string `json:"label" msgpack:"label" bson:"-" mapstructure:"label,omitempty"`

	// The name of the detection.
	Name string `json:"name" msgpack:"name" bson:"-" mapstructure:"name,omitempty"`

	// Tell if the detection is positional.
	Positional bool `json:"positional" msgpack:"positional" bson:"-" mapstructure:"positional,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewDetector returns a new *Detector
func NewDetector() *Detector {

	return &Detector{
		ModelVersion: 1,
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Detector) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesDetector{}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Detector) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesDetector{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *Detector) BleveType() string {

	return "detector"
}

// DeepCopy returns a deep copy if the Detector.
func (o *Detector) DeepCopy() *Detector {

	if o == nil {
		return nil
	}

	out := &Detector{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Detector.
func (o *Detector) DeepCopyInto(out *Detector) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Detector: %s", err))
	}

	*out = *target.(*Detector)
}

// Validate valides the current information stored into the structure.
func (o *Detector) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if len(requiredErrors) > 0 {
		return requiredErrors
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// SpecificationForAttribute returns the AttributeSpecification for the given attribute name key.
func (*Detector) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := DetectorAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return DetectorLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Detector) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return DetectorAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Detector) ValueForAttribute(name string) any {

	switch name {
	case "description":
		return o.Description
	case "group":
		return o.Group
	case "label":
		return o.Label
	case "name":
		return o.Name
	case "positional":
		return o.Positional
	}

	return nil
}

// DetectorAttributesMap represents the map of attribute for Detector.
var DetectorAttributesMap = map[string]elemental.AttributeSpecification{
	"Description": {
		AllowedChoices: []string{},
		ConvertedName:  "Description",
		Description:    `The description of the detection.`,
		Exposed:        true,
		Name:           "description",
		Type:           "string",
	},
	"Group": {
		AllowedChoices: []string{},
		ConvertedName:  "Group",
		Description:    `The group the detection belongs to.`,
		Exposed:        true,
		Name:           "group",
		Type:           "string",
	},
	"Label": {
		AllowedChoices: []string{},
		ConvertedName:  "Label",
		Description:    `The label returned by the model.`,
		Exposed:        true,
		Name:           "label",
		Type:           "string",
	},
	"Name": {
		AllowedChoices: []string{},
		ConvertedName:  "Name",
		Description:    `The name of the detection.`,
		Exposed:        true,
		Name:           "name",
		Type:           "string",
	},
	"Positional": {
		AllowedChoices: []string{},
		ConvertedName:  "Positional",
		Description:    `Tell if the detection is positional.`,
		Exposed:        true,
		Name:           "positional",
		Type:           "boolean",
	},
}

// DetectorLowerCaseAttributesMap represents the map of attribute for Detector.
var DetectorLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"description": {
		AllowedChoices: []string{},
		ConvertedName:  "Description",
		Description:    `The description of the detection.`,
		Exposed:        true,
		Name:           "description",
		Type:           "string",
	},
	"group": {
		AllowedChoices: []string{},
		ConvertedName:  "Group",
		Description:    `The group the detection belongs to.`,
		Exposed:        true,
		Name:           "group",
		Type:           "string",
	},
	"label": {
		AllowedChoices: []string{},
		ConvertedName:  "Label",
		Description:    `The label returned by the model.`,
		Exposed:        true,
		Name:           "label",
		Type:           "string",
	},
	"name": {
		AllowedChoices: []string{},
		ConvertedName:  "Name",
		Description:    `The name of the detection.`,
		Exposed:        true,
		Name:           "name",
		Type:           "string",
	},
	"positional": {
		AllowedChoices: []string{},
		ConvertedName:  "Positional",
		Description:    `Tell if the detection is positional.`,
		Exposed:        true,
		Name:           "positional",
		Type:           "boolean",
	},
}

type mongoAttributesDetector struct {
}
