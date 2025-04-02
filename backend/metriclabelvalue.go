// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// MetricLabelValueIdentity represents the Identity of the object.
var MetricLabelValueIdentity = elemental.Identity{
	Name:     "metriclabelvalue",
	Category: "metriclabelvalues",
	Package:  "snitch",
	Private:  false,
}

// MetricLabelValuesList represents a list of MetricLabelValues
type MetricLabelValuesList []*MetricLabelValue

// Identity returns the identity of the objects in the list.
func (o MetricLabelValuesList) Identity() elemental.Identity {

	return MetricLabelValueIdentity
}

// Copy returns a pointer to a copy the MetricLabelValuesList.
func (o MetricLabelValuesList) Copy() elemental.Identifiables {

	out := append(MetricLabelValuesList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the MetricLabelValuesList.
func (o MetricLabelValuesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(MetricLabelValuesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*MetricLabelValue))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o MetricLabelValuesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o MetricLabelValuesList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the MetricLabelValuesList converted to SparseMetricLabelValuesList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o MetricLabelValuesList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseMetricLabelValuesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseMetricLabelValue)
	}

	return out
}

// Version returns the version of the content.
func (o MetricLabelValuesList) Version() int {

	return 1
}

// MetricLabelValue represents the model of a metriclabelvalue
type MetricLabelValue struct {
	// ID is the identifier of the object.
	ID string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The end of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	End string `json:"end,omitempty" msgpack:"end,omitempty" bson:"-" mapstructure:"end,omitempty"`

	// The relative end of the time window as time.Duration.
	EndRelative string `json:"endRelative,omitempty" msgpack:"endRelative,omitempty" bson:"-" mapstructure:"endRelative,omitempty"`

	// The label to retrieve all available values for.
	Label string `json:"label" msgpack:"label" bson:"-" mapstructure:"label,omitempty"`

	// The max number of results to return.
	Limit int `json:"limit" msgpack:"limit" bson:"-" mapstructure:"limit,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// A set of metric stream selectors that selects the streams to match and return
	// label values for.
	Query string `json:"query,omitempty" msgpack:"query,omitempty" bson:"-" mapstructure:"query,omitempty"`

	// The result of the request.
	Result []string `json:"result" msgpack:"result" bson:"-" mapstructure:"result,omitempty"`

	// The start of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	Start string `json:"start,omitempty" msgpack:"start,omitempty" bson:"-" mapstructure:"start,omitempty"`

	// The relative start of the time window as time.Duration.
	StartRelative string `json:"startRelative,omitempty" msgpack:"startRelative,omitempty" bson:"-" mapstructure:"startRelative,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewMetricLabelValue returns a new *MetricLabelValue
func NewMetricLabelValue() *MetricLabelValue {

	return &MetricLabelValue{
		ModelVersion: 1,
		Limit:        100,
		Result:       []string{},
	}
}

// Identity returns the Identity of the object.
func (o *MetricLabelValue) Identity() elemental.Identity {

	return MetricLabelValueIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *MetricLabelValue) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *MetricLabelValue) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *MetricLabelValue) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesMetricLabelValue{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.Namespace = o.Namespace

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *MetricLabelValue) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesMetricLabelValue{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.Namespace = s.Namespace

	return nil
}

// Version returns the hardcoded version of the model.
func (o *MetricLabelValue) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *MetricLabelValue) BleveType() string {

	return "metriclabelvalue"
}

// DefaultOrder returns the list of default ordering fields.
func (o *MetricLabelValue) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *MetricLabelValue) Doc() string {

	return `Get all metric values for a given label.`
}

func (o *MetricLabelValue) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetEnd returns the End of the receiver.
func (o *MetricLabelValue) GetEnd() string {

	return o.End
}

// SetEnd sets the property End of the receiver using the given value.
func (o *MetricLabelValue) SetEnd(end string) {

	o.End = end
}

// GetEndRelative returns the EndRelative of the receiver.
func (o *MetricLabelValue) GetEndRelative() string {

	return o.EndRelative
}

// GetNamespace returns the Namespace of the receiver.
func (o *MetricLabelValue) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *MetricLabelValue) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// GetStart returns the Start of the receiver.
func (o *MetricLabelValue) GetStart() string {

	return o.Start
}

// SetStart sets the property Start of the receiver using the given value.
func (o *MetricLabelValue) SetStart(start string) {

	o.Start = start
}

// GetStartRelative returns the StartRelative of the receiver.
func (o *MetricLabelValue) GetStartRelative() string {

	return o.StartRelative
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *MetricLabelValue) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseMetricLabelValue{
			ID:            &o.ID,
			End:           &o.End,
			EndRelative:   &o.EndRelative,
			Label:         &o.Label,
			Limit:         &o.Limit,
			Namespace:     &o.Namespace,
			Query:         &o.Query,
			Result:        &o.Result,
			Start:         &o.Start,
			StartRelative: &o.StartRelative,
		}
	}

	sp := &SparseMetricLabelValue{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "end":
			sp.End = &(o.End)
		case "endRelative":
			sp.EndRelative = &(o.EndRelative)
		case "label":
			sp.Label = &(o.Label)
		case "limit":
			sp.Limit = &(o.Limit)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "query":
			sp.Query = &(o.Query)
		case "result":
			sp.Result = &(o.Result)
		case "start":
			sp.Start = &(o.Start)
		case "startRelative":
			sp.StartRelative = &(o.StartRelative)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseMetricLabelValue to the object.
func (o *MetricLabelValue) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseMetricLabelValue)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.End != nil {
		o.End = *so.End
	}
	if so.EndRelative != nil {
		o.EndRelative = *so.EndRelative
	}
	if so.Label != nil {
		o.Label = *so.Label
	}
	if so.Limit != nil {
		o.Limit = *so.Limit
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.Query != nil {
		o.Query = *so.Query
	}
	if so.Result != nil {
		o.Result = *so.Result
	}
	if so.Start != nil {
		o.Start = *so.Start
	}
	if so.StartRelative != nil {
		o.StartRelative = *so.StartRelative
	}
}

// DeepCopy returns a deep copy if the MetricLabelValue.
func (o *MetricLabelValue) DeepCopy() *MetricLabelValue {

	if o == nil {
		return nil
	}

	out := &MetricLabelValue{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *MetricLabelValue.
func (o *MetricLabelValue) DeepCopyInto(out *MetricLabelValue) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy MetricLabelValue: %s", err))
	}

	*out = *target.(*MetricLabelValue)
}

// Validate valides the current information stored into the structure.
func (o *MetricLabelValue) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := ValidateDuration("endRelative", o.EndRelative); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("label", o.Label); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidateDuration("startRelative", o.StartRelative); err != nil {
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
func (*MetricLabelValue) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := MetricLabelValueAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return MetricLabelValueLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*MetricLabelValue) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return MetricLabelValueAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *MetricLabelValue) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "end":
		return o.End
	case "endRelative":
		return o.EndRelative
	case "label":
		return o.Label
	case "limit":
		return o.Limit
	case "namespace":
		return o.Namespace
	case "query":
		return o.Query
	case "result":
		return o.Result
	case "start":
		return o.Start
	case "startRelative":
		return o.StartRelative
	}

	return nil
}

// MetricLabelValueAttributesMap represents the map of attribute for MetricLabelValue.
var MetricLabelValueAttributesMap = map[string]elemental.AttributeSpecification{
	"ID": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "_id",
		ConvertedName:  "ID",
		Description:    `ID is the identifier of the object.`,
		Exposed:        true,
		Filterable:     true,
		Identifier:     true,
		Name:           "ID",
		Orderable:      true,
		ReadOnly:       true,
		Stored:         true,
		Type:           "string",
	},
	"End": {
		AllowedChoices: []string{},
		ConvertedName:  "End",
		Description: `The end of the time window in any format supported by
https://github.com/araddon/dateparse.`,
		Exposed: true,
		Getter:  true,
		Name:    "end",
		Setter:  true,
		Type:    "string",
	},
	"EndRelative": {
		AllowedChoices: []string{},
		ConvertedName:  "EndRelative",
		Description:    `The relative end of the time window as time.Duration.`,
		Exposed:        true,
		Getter:         true,
		Name:           "endRelative",
		Type:           "string",
	},
	"Label": {
		AllowedChoices: []string{},
		ConvertedName:  "Label",
		Description:    `The label to retrieve all available values for.`,
		Exposed:        true,
		Name:           "label",
		Required:       true,
		Type:           "string",
	},
	"Limit": {
		AllowedChoices: []string{},
		ConvertedName:  "Limit",
		DefaultValue:   100,
		Description:    `The max number of results to return.`,
		Exposed:        true,
		Name:           "limit",
		Type:           "integer",
	},
	"Namespace": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "namespace",
		ConvertedName:  "Namespace",
		Description:    `The namespace of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "namespace",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"Query": {
		AllowedChoices: []string{},
		ConvertedName:  "Query",
		Description: `A set of metric stream selectors that selects the streams to match and return
label values for.`,
		Exposed: true,
		Name:    "query",
		Type:    "string",
	},
	"Result": {
		AllowedChoices: []string{},
		ConvertedName:  "Result",
		Description:    `The result of the request.`,
		Exposed:        true,
		Name:           "result",
		SubType:        "string",
		Type:           "list",
	},
	"Start": {
		AllowedChoices: []string{},
		ConvertedName:  "Start",
		Description: `The start of the time window in any format supported by
https://github.com/araddon/dateparse.`,
		Exposed: true,
		Getter:  true,
		Name:    "start",
		Setter:  true,
		Type:    "string",
	},
	"StartRelative": {
		AllowedChoices: []string{},
		ConvertedName:  "StartRelative",
		Description:    `The relative start of the time window as time.Duration.`,
		Exposed:        true,
		Getter:         true,
		Name:           "startRelative",
		Type:           "string",
	},
}

// MetricLabelValueLowerCaseAttributesMap represents the map of attribute for MetricLabelValue.
var MetricLabelValueLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"id": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "_id",
		ConvertedName:  "ID",
		Description:    `ID is the identifier of the object.`,
		Exposed:        true,
		Filterable:     true,
		Identifier:     true,
		Name:           "ID",
		Orderable:      true,
		ReadOnly:       true,
		Stored:         true,
		Type:           "string",
	},
	"end": {
		AllowedChoices: []string{},
		ConvertedName:  "End",
		Description: `The end of the time window in any format supported by
https://github.com/araddon/dateparse.`,
		Exposed: true,
		Getter:  true,
		Name:    "end",
		Setter:  true,
		Type:    "string",
	},
	"endrelative": {
		AllowedChoices: []string{},
		ConvertedName:  "EndRelative",
		Description:    `The relative end of the time window as time.Duration.`,
		Exposed:        true,
		Getter:         true,
		Name:           "endRelative",
		Type:           "string",
	},
	"label": {
		AllowedChoices: []string{},
		ConvertedName:  "Label",
		Description:    `The label to retrieve all available values for.`,
		Exposed:        true,
		Name:           "label",
		Required:       true,
		Type:           "string",
	},
	"limit": {
		AllowedChoices: []string{},
		ConvertedName:  "Limit",
		DefaultValue:   100,
		Description:    `The max number of results to return.`,
		Exposed:        true,
		Name:           "limit",
		Type:           "integer",
	},
	"namespace": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "namespace",
		ConvertedName:  "Namespace",
		Description:    `The namespace of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "namespace",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"query": {
		AllowedChoices: []string{},
		ConvertedName:  "Query",
		Description: `A set of metric stream selectors that selects the streams to match and return
label values for.`,
		Exposed: true,
		Name:    "query",
		Type:    "string",
	},
	"result": {
		AllowedChoices: []string{},
		ConvertedName:  "Result",
		Description:    `The result of the request.`,
		Exposed:        true,
		Name:           "result",
		SubType:        "string",
		Type:           "list",
	},
	"start": {
		AllowedChoices: []string{},
		ConvertedName:  "Start",
		Description: `The start of the time window in any format supported by
https://github.com/araddon/dateparse.`,
		Exposed: true,
		Getter:  true,
		Name:    "start",
		Setter:  true,
		Type:    "string",
	},
	"startrelative": {
		AllowedChoices: []string{},
		ConvertedName:  "StartRelative",
		Description:    `The relative start of the time window as time.Duration.`,
		Exposed:        true,
		Getter:         true,
		Name:           "startRelative",
		Type:           "string",
	},
}

// SparseMetricLabelValuesList represents a list of SparseMetricLabelValues
type SparseMetricLabelValuesList []*SparseMetricLabelValue

// Identity returns the identity of the objects in the list.
func (o SparseMetricLabelValuesList) Identity() elemental.Identity {

	return MetricLabelValueIdentity
}

// Copy returns a pointer to a copy the SparseMetricLabelValuesList.
func (o SparseMetricLabelValuesList) Copy() elemental.Identifiables {

	copy := append(SparseMetricLabelValuesList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseMetricLabelValuesList.
func (o SparseMetricLabelValuesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseMetricLabelValuesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseMetricLabelValue))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseMetricLabelValuesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseMetricLabelValuesList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseMetricLabelValuesList converted to MetricLabelValuesList.
func (o SparseMetricLabelValuesList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseMetricLabelValuesList) Version() int {

	return 1
}

// SparseMetricLabelValue represents the sparse version of a metriclabelvalue.
type SparseMetricLabelValue struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The end of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	End *string `json:"end,omitempty" msgpack:"end,omitempty" bson:"-" mapstructure:"end,omitempty"`

	// The relative end of the time window as time.Duration.
	EndRelative *string `json:"endRelative,omitempty" msgpack:"endRelative,omitempty" bson:"-" mapstructure:"endRelative,omitempty"`

	// The label to retrieve all available values for.
	Label *string `json:"label,omitempty" msgpack:"label,omitempty" bson:"-" mapstructure:"label,omitempty"`

	// The max number of results to return.
	Limit *int `json:"limit,omitempty" msgpack:"limit,omitempty" bson:"-" mapstructure:"limit,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// A set of metric stream selectors that selects the streams to match and return
	// label values for.
	Query *string `json:"query,omitempty" msgpack:"query,omitempty" bson:"-" mapstructure:"query,omitempty"`

	// The result of the request.
	Result *[]string `json:"result,omitempty" msgpack:"result,omitempty" bson:"-" mapstructure:"result,omitempty"`

	// The start of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	Start *string `json:"start,omitempty" msgpack:"start,omitempty" bson:"-" mapstructure:"start,omitempty"`

	// The relative start of the time window as time.Duration.
	StartRelative *string `json:"startRelative,omitempty" msgpack:"startRelative,omitempty" bson:"-" mapstructure:"startRelative,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseMetricLabelValue returns a new  SparseMetricLabelValue.
func NewSparseMetricLabelValue() *SparseMetricLabelValue {
	return &SparseMetricLabelValue{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseMetricLabelValue) Identity() elemental.Identity {

	return MetricLabelValueIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseMetricLabelValue) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseMetricLabelValue) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseMetricLabelValue) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseMetricLabelValue{}

	if o.ID != nil {
		s.ID = bson.ObjectIdHex(*o.ID)
	}
	if o.Namespace != nil {
		s.Namespace = o.Namespace
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseMetricLabelValue) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseMetricLabelValue{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	id := s.ID.Hex()
	o.ID = &id
	if s.Namespace != nil {
		o.Namespace = s.Namespace
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseMetricLabelValue) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseMetricLabelValue) ToPlain() elemental.PlainIdentifiable {

	out := NewMetricLabelValue()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.End != nil {
		out.End = *o.End
	}
	if o.EndRelative != nil {
		out.EndRelative = *o.EndRelative
	}
	if o.Label != nil {
		out.Label = *o.Label
	}
	if o.Limit != nil {
		out.Limit = *o.Limit
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.Query != nil {
		out.Query = *o.Query
	}
	if o.Result != nil {
		out.Result = *o.Result
	}
	if o.Start != nil {
		out.Start = *o.Start
	}
	if o.StartRelative != nil {
		out.StartRelative = *o.StartRelative
	}

	return out
}

// GetEnd returns the End of the receiver.
func (o *SparseMetricLabelValue) GetEnd() (out string) {

	if o.End == nil {
		return
	}

	return *o.End
}

// SetEnd sets the property End of the receiver using the address of the given value.
func (o *SparseMetricLabelValue) SetEnd(end string) {

	o.End = &end
}

// GetEndRelative returns the EndRelative of the receiver.
func (o *SparseMetricLabelValue) GetEndRelative() (out string) {

	if o.EndRelative == nil {
		return
	}

	return *o.EndRelative
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseMetricLabelValue) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseMetricLabelValue) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// GetStart returns the Start of the receiver.
func (o *SparseMetricLabelValue) GetStart() (out string) {

	if o.Start == nil {
		return
	}

	return *o.Start
}

// SetStart sets the property Start of the receiver using the address of the given value.
func (o *SparseMetricLabelValue) SetStart(start string) {

	o.Start = &start
}

// GetStartRelative returns the StartRelative of the receiver.
func (o *SparseMetricLabelValue) GetStartRelative() (out string) {

	if o.StartRelative == nil {
		return
	}

	return *o.StartRelative
}

// DeepCopy returns a deep copy if the SparseMetricLabelValue.
func (o *SparseMetricLabelValue) DeepCopy() *SparseMetricLabelValue {

	if o == nil {
		return nil
	}

	out := &SparseMetricLabelValue{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseMetricLabelValue.
func (o *SparseMetricLabelValue) DeepCopyInto(out *SparseMetricLabelValue) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseMetricLabelValue: %s", err))
	}

	*out = *target.(*SparseMetricLabelValue)
}

type mongoAttributesMetricLabelValue struct {
	ID        bson.ObjectId `bson:"_id,omitempty"`
	Namespace string        `bson:"namespace,omitempty"`
}
type mongoAttributesSparseMetricLabelValue struct {
	ID        bson.ObjectId `bson:"_id,omitempty"`
	Namespace *string       `bson:"namespace,omitempty"`
}
