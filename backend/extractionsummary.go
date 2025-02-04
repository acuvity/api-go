// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// ExtractionSummary represents the model of a extractionsummary
type ExtractionSummary struct {
	// The PIIs found during classification.
	PIIs map[string]ExtractionInformation `json:"PIIs,omitempty" msgpack:"PIIs,omitempty" bson:"piis,omitempty" mapstructure:"PIIs,omitempty"`

	// The categories are remapping of the modalities in a more human friendly way.
	Categories map[string]ExtractionInformation `json:"categories,omitempty" msgpack:"categories,omitempty" bson:"categories,omitempty" mapstructure:"categories,omitempty"`

	// The various exploits attempts.
	Exploits map[string]ExtractionInformation `json:"exploits,omitempty" msgpack:"exploits,omitempty" bson:"exploits,omitempty" mapstructure:"exploits,omitempty"`

	// The estimated intent embodied into the text.
	Intent map[string]ExtractionInformation `json:"intent,omitempty" msgpack:"intent,omitempty" bson:"intent,omitempty" mapstructure:"intent,omitempty"`

	// The keywords found during classification.
	Keywords map[string]ExtractionInformation `json:"keywords,omitempty" msgpack:"keywords,omitempty" bson:"keywords,omitempty" mapstructure:"keywords,omitempty"`

	// The language of the classification.
	Languages map[string]ExtractionInformation `json:"languages,omitempty" msgpack:"languages,omitempty" bson:"languages,omitempty" mapstructure:"languages,omitempty"`

	// The modalities of data detected in the data.
	Modalities map[string]ExtractionInformation `json:"modalities,omitempty" msgpack:"modalities,omitempty" bson:"modalities,omitempty" mapstructure:"modalities,omitempty"`

	// The secrets found during classification.
	Secrets map[string]ExtractionInformation `json:"secrets,omitempty" msgpack:"secrets,omitempty" bson:"secrets,omitempty" mapstructure:"secrets,omitempty"`

	// The topic of the classification.
	Topics map[string]ExtractionInformation `json:"topics,omitempty" msgpack:"topics,omitempty" bson:"topics,omitempty" mapstructure:"topics,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewExtractionSummary returns a new *ExtractionSummary
func NewExtractionSummary() *ExtractionSummary {

	return &ExtractionSummary{
		ModelVersion: 1,
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *ExtractionSummary) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesExtractionSummary{}

	s.PIIs = o.PIIs
	s.Categories = o.Categories
	s.Exploits = o.Exploits
	s.Intent = o.Intent
	s.Keywords = o.Keywords
	s.Languages = o.Languages
	s.Modalities = o.Modalities
	s.Secrets = o.Secrets
	s.Topics = o.Topics

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *ExtractionSummary) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesExtractionSummary{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.PIIs = s.PIIs
	o.Categories = s.Categories
	o.Exploits = s.Exploits
	o.Intent = s.Intent
	o.Keywords = s.Keywords
	o.Languages = s.Languages
	o.Modalities = s.Modalities
	o.Secrets = s.Secrets
	o.Topics = s.Topics

	return nil
}

// BleveType implements the bleve.Classifier Interface.
func (o *ExtractionSummary) BleveType() string {

	return "extractionsummary"
}

// DeepCopy returns a deep copy if the ExtractionSummary.
func (o *ExtractionSummary) DeepCopy() *ExtractionSummary {

	if o == nil {
		return nil
	}

	out := &ExtractionSummary{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *ExtractionSummary.
func (o *ExtractionSummary) DeepCopyInto(out *ExtractionSummary) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy ExtractionSummary: %s", err))
	}

	*out = *target.(*ExtractionSummary)
}

// Validate valides the current information stored into the structure.
func (o *ExtractionSummary) Validate() error {

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
func (*ExtractionSummary) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := ExtractionSummaryAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return ExtractionSummaryLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*ExtractionSummary) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return ExtractionSummaryAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *ExtractionSummary) ValueForAttribute(name string) any {

	switch name {
	case "PIIs":
		return o.PIIs
	case "categories":
		return o.Categories
	case "exploits":
		return o.Exploits
	case "intent":
		return o.Intent
	case "keywords":
		return o.Keywords
	case "languages":
		return o.Languages
	case "modalities":
		return o.Modalities
	case "secrets":
		return o.Secrets
	case "topics":
		return o.Topics
	}

	return nil
}

// ExtractionSummaryAttributesMap represents the map of attribute for ExtractionSummary.
var ExtractionSummaryAttributesMap = map[string]elemental.AttributeSpecification{
	"PIIs": {
		AllowedChoices: []string{},
		BSONFieldName:  "piis",
		ConvertedName:  "PIIs",
		Description:    `The PIIs found during classification.`,
		Exposed:        true,
		Name:           "PIIs",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Categories": {
		AllowedChoices: []string{},
		BSONFieldName:  "categories",
		ConvertedName:  "Categories",
		Description:    `The categories are remapping of the modalities in a more human friendly way.`,
		Exposed:        true,
		Name:           "categories",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Exploits": {
		AllowedChoices: []string{},
		BSONFieldName:  "exploits",
		ConvertedName:  "Exploits",
		Description:    `The various exploits attempts.`,
		Exposed:        true,
		Name:           "exploits",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Intent": {
		AllowedChoices: []string{},
		BSONFieldName:  "intent",
		ConvertedName:  "Intent",
		Description:    `The estimated intent embodied into the text.`,
		Exposed:        true,
		Name:           "intent",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Keywords": {
		AllowedChoices: []string{},
		BSONFieldName:  "keywords",
		ConvertedName:  "Keywords",
		Description:    `The keywords found during classification.`,
		Exposed:        true,
		Name:           "keywords",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Languages": {
		AllowedChoices: []string{},
		BSONFieldName:  "languages",
		ConvertedName:  "Languages",
		Description:    `The language of the classification.`,
		Exposed:        true,
		Name:           "languages",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Modalities": {
		AllowedChoices: []string{},
		BSONFieldName:  "modalities",
		ConvertedName:  "Modalities",
		Description:    `The modalities of data detected in the data.`,
		Exposed:        true,
		Name:           "modalities",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Secrets": {
		AllowedChoices: []string{},
		BSONFieldName:  "secrets",
		ConvertedName:  "Secrets",
		Description:    `The secrets found during classification.`,
		Exposed:        true,
		Name:           "secrets",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"Topics": {
		AllowedChoices: []string{},
		BSONFieldName:  "topics",
		ConvertedName:  "Topics",
		Description:    `The topic of the classification.`,
		Exposed:        true,
		Name:           "topics",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
}

// ExtractionSummaryLowerCaseAttributesMap represents the map of attribute for ExtractionSummary.
var ExtractionSummaryLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"piis": {
		AllowedChoices: []string{},
		BSONFieldName:  "piis",
		ConvertedName:  "PIIs",
		Description:    `The PIIs found during classification.`,
		Exposed:        true,
		Name:           "PIIs",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"categories": {
		AllowedChoices: []string{},
		BSONFieldName:  "categories",
		ConvertedName:  "Categories",
		Description:    `The categories are remapping of the modalities in a more human friendly way.`,
		Exposed:        true,
		Name:           "categories",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"exploits": {
		AllowedChoices: []string{},
		BSONFieldName:  "exploits",
		ConvertedName:  "Exploits",
		Description:    `The various exploits attempts.`,
		Exposed:        true,
		Name:           "exploits",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"intent": {
		AllowedChoices: []string{},
		BSONFieldName:  "intent",
		ConvertedName:  "Intent",
		Description:    `The estimated intent embodied into the text.`,
		Exposed:        true,
		Name:           "intent",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"keywords": {
		AllowedChoices: []string{},
		BSONFieldName:  "keywords",
		ConvertedName:  "Keywords",
		Description:    `The keywords found during classification.`,
		Exposed:        true,
		Name:           "keywords",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"languages": {
		AllowedChoices: []string{},
		BSONFieldName:  "languages",
		ConvertedName:  "Languages",
		Description:    `The language of the classification.`,
		Exposed:        true,
		Name:           "languages",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"modalities": {
		AllowedChoices: []string{},
		BSONFieldName:  "modalities",
		ConvertedName:  "Modalities",
		Description:    `The modalities of data detected in the data.`,
		Exposed:        true,
		Name:           "modalities",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"secrets": {
		AllowedChoices: []string{},
		BSONFieldName:  "secrets",
		ConvertedName:  "Secrets",
		Description:    `The secrets found during classification.`,
		Exposed:        true,
		Name:           "secrets",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
	"topics": {
		AllowedChoices: []string{},
		BSONFieldName:  "topics",
		ConvertedName:  "Topics",
		Description:    `The topic of the classification.`,
		Exposed:        true,
		Name:           "topics",
		Stored:         true,
		SubType:        "map[string]extractioninformation",
		Type:           "external",
	},
}

type mongoAttributesExtractionSummary struct {
	PIIs       map[string]ExtractionInformation `bson:"piis,omitempty"`
	Categories map[string]ExtractionInformation `bson:"categories,omitempty"`
	Exploits   map[string]ExtractionInformation `bson:"exploits,omitempty"`
	Intent     map[string]ExtractionInformation `bson:"intent,omitempty"`
	Keywords   map[string]ExtractionInformation `bson:"keywords,omitempty"`
	Languages  map[string]ExtractionInformation `bson:"languages,omitempty"`
	Modalities map[string]ExtractionInformation `bson:"modalities,omitempty"`
	Secrets    map[string]ExtractionInformation `bson:"secrets,omitempty"`
	Topics     map[string]ExtractionInformation `bson:"topics,omitempty"`
}
