// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// ModerationActionValue represents the possible values for attribute "action".
type ModerationActionValue string

const (
	// ModerationActionBlock represents the value Block.
	ModerationActionBlock ModerationActionValue = "Block"

	// ModerationActionNone represents the value None.
	ModerationActionNone ModerationActionValue = "None"

	// ModerationActionWarn represents the value Warn.
	ModerationActionWarn ModerationActionValue = "Warn"
)

// Moderation represents the model of a moderation
type Moderation struct {
	// The actual action to take when triggered.
	Action ModerationActionValue `json:"action" msgpack:"action" bson:"action" mapstructure:"action,omitempty"`

	// The definition to use for alerting.
	AlertDefinition string `json:"alertDefinition" msgpack:"alertDefinition" bson:"alertdefinition" mapstructure:"alertDefinition,omitempty"`

	// Sets an optional link to reference a document with more explanation on the
	// moderation.
	Link string `json:"link,omitempty" msgpack:"link,omitempty" bson:"link,omitempty" mapstructure:"link,omitempty"`

	// The message if the moderation action is warn or block.
	Message string `json:"message" msgpack:"message" bson:"message" mapstructure:"message,omitempty"`

	// The predicate expression for the moderation to be triggered.
	Predicates []*Predicate `json:"predicates" msgpack:"predicates" bson:"predicates" mapstructure:"predicates,omitempty"`

	// If true, redacts the keywords, PIIs, and/or secrets defined in the predicates.
	Redact bool `json:"redact" msgpack:"redact" bson:"redact" mapstructure:"redact,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewModeration returns a new *Moderation
func NewModeration() *Moderation {

	return &Moderation{
		ModelVersion: 1,
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Moderation) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesModeration{}

	s.Action = o.Action
	s.AlertDefinition = o.AlertDefinition
	s.Link = o.Link
	s.Message = o.Message
	s.Predicates = o.Predicates
	s.Redact = o.Redact

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Moderation) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesModeration{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.Action = s.Action
	o.AlertDefinition = s.AlertDefinition
	o.Link = s.Link
	o.Message = s.Message
	o.Predicates = s.Predicates
	o.Redact = s.Redact

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *Moderation) BleveType() string {

	return "moderation"
}

// DeepCopy returns a deep copy if the Moderation.
func (o *Moderation) DeepCopy() *Moderation {

	if o == nil {
		return nil
	}

	out := &Moderation{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Moderation.
func (o *Moderation) DeepCopyInto(out *Moderation) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Moderation: %s", err))
	}

	*out = *target.(*Moderation)
}

// Validate valides the current information stored into the structure.
func (o *Moderation) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("action", string(o.Action)); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateStringInList("action", string(o.Action), []string{"Warn", "Block", "None"}, false); err != nil {
		errors = errors.Append(err)
	}

	for _, sub := range o.Predicates {
		if sub == nil {
			continue
		}
		elemental.ResetDefaultForZeroValues(sub)
		if err := sub.Validate(); err != nil {
			errors = errors.Append(err)
		}
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
func (*Moderation) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := ModerationAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return ModerationLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Moderation) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return ModerationAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Moderation) ValueForAttribute(name string) any {

	switch name {
	case "action":
		return o.Action
	case "alertDefinition":
		return o.AlertDefinition
	case "link":
		return o.Link
	case "message":
		return o.Message
	case "predicates":
		return o.Predicates
	case "redact":
		return o.Redact
	}

	return nil
}

// ModerationAttributesMap represents the map of attribute for Moderation.
var ModerationAttributesMap = map[string]elemental.AttributeSpecification{
	"Action": {
		AllowedChoices: []string{"Warn", "Block", "None"},
		BSONFieldName:  "action",
		ConvertedName:  "Action",
		Description:    `The actual action to take when triggered.`,
		Exposed:        true,
		Name:           "action",
		Required:       true,
		Stored:         true,
		Type:           "enum",
	},
	"AlertDefinition": {
		AllowedChoices: []string{},
		BSONFieldName:  "alertdefinition",
		ConvertedName:  "AlertDefinition",
		Description:    `The definition to use for alerting.`,
		Exposed:        true,
		Name:           "alertDefinition",
		Stored:         true,
		Type:           "string",
	},
	"Link": {
		AllowedChoices: []string{},
		BSONFieldName:  "link",
		ConvertedName:  "Link",
		Description: `Sets an optional link to reference a document with more explanation on the
moderation.`,
		Exposed: true,
		Name:    "link",
		Stored:  true,
		Type:    "string",
	},
	"Message": {
		AllowedChoices: []string{},
		BSONFieldName:  "message",
		ConvertedName:  "Message",
		Description:    `The message if the moderation action is warn or block.`,
		Exposed:        true,
		Name:           "message",
		Stored:         true,
		Type:           "string",
	},
	"Predicates": {
		AllowedChoices: []string{},
		BSONFieldName:  "predicates",
		ConvertedName:  "Predicates",
		Description:    `The predicate expression for the moderation to be triggered.`,
		Exposed:        true,
		Name:           "predicates",
		Stored:         true,
		SubType:        "predicate",
		Type:           "refList",
	},
	"Redact": {
		AllowedChoices: []string{},
		BSONFieldName:  "redact",
		ConvertedName:  "Redact",
		Description:    `If true, redacts the keywords, PIIs, and/or secrets defined in the predicates.`,
		Exposed:        true,
		Name:           "redact",
		Stored:         true,
		Type:           "boolean",
	},
}

// ModerationLowerCaseAttributesMap represents the map of attribute for Moderation.
var ModerationLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"action": {
		AllowedChoices: []string{"Warn", "Block", "None"},
		BSONFieldName:  "action",
		ConvertedName:  "Action",
		Description:    `The actual action to take when triggered.`,
		Exposed:        true,
		Name:           "action",
		Required:       true,
		Stored:         true,
		Type:           "enum",
	},
	"alertdefinition": {
		AllowedChoices: []string{},
		BSONFieldName:  "alertdefinition",
		ConvertedName:  "AlertDefinition",
		Description:    `The definition to use for alerting.`,
		Exposed:        true,
		Name:           "alertDefinition",
		Stored:         true,
		Type:           "string",
	},
	"link": {
		AllowedChoices: []string{},
		BSONFieldName:  "link",
		ConvertedName:  "Link",
		Description: `Sets an optional link to reference a document with more explanation on the
moderation.`,
		Exposed: true,
		Name:    "link",
		Stored:  true,
		Type:    "string",
	},
	"message": {
		AllowedChoices: []string{},
		BSONFieldName:  "message",
		ConvertedName:  "Message",
		Description:    `The message if the moderation action is warn or block.`,
		Exposed:        true,
		Name:           "message",
		Stored:         true,
		Type:           "string",
	},
	"predicates": {
		AllowedChoices: []string{},
		BSONFieldName:  "predicates",
		ConvertedName:  "Predicates",
		Description:    `The predicate expression for the moderation to be triggered.`,
		Exposed:        true,
		Name:           "predicates",
		Stored:         true,
		SubType:        "predicate",
		Type:           "refList",
	},
	"redact": {
		AllowedChoices: []string{},
		BSONFieldName:  "redact",
		ConvertedName:  "Redact",
		Description:    `If true, redacts the keywords, PIIs, and/or secrets defined in the predicates.`,
		Exposed:        true,
		Name:           "redact",
		Stored:         true,
		Type:           "boolean",
	},
}

type mongoAttributesModeration struct {
	Action          ModerationActionValue `bson:"action"`
	AlertDefinition string                `bson:"alertdefinition"`
	Link            string                `bson:"link,omitempty"`
	Message         string                `bson:"message"`
	Predicates      []*Predicate          `bson:"predicates"`
	Redact          bool                  `bson:"redact"`
}
