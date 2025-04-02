// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// MetricSerieIdentity represents the Identity of the object.
var MetricSerieIdentity = elemental.Identity{
	Name:     "metricserie",
	Category: "metricseries",
	Package:  "snitch",
	Private:  false,
}

// MetricSeriesList represents a list of MetricSeries
type MetricSeriesList []*MetricSerie

// Identity returns the identity of the objects in the list.
func (o MetricSeriesList) Identity() elemental.Identity {

	return MetricSerieIdentity
}

// Copy returns a pointer to a copy the MetricSeriesList.
func (o MetricSeriesList) Copy() elemental.Identifiables {

	out := append(MetricSeriesList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the MetricSeriesList.
func (o MetricSeriesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(MetricSeriesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*MetricSerie))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o MetricSeriesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o MetricSeriesList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the MetricSeriesList converted to SparseMetricSeriesList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o MetricSeriesList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseMetricSeriesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseMetricSerie)
	}

	return out
}

// Version returns the version of the content.
func (o MetricSeriesList) Version() int {

	return 1
}

// MetricSerie represents the model of a metricserie
type MetricSerie struct {
	// ID is the identifier of the object.
	ID string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The end of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	End string `json:"end,omitempty" msgpack:"end,omitempty" bson:"-" mapstructure:"end,omitempty"`

	// The relative end of the time window as time.Duration.
	EndRelative string `json:"endRelative,omitempty" msgpack:"endRelative,omitempty" bson:"-" mapstructure:"endRelative,omitempty"`

	// The max number of results to return.
	Limit int `json:"limit" msgpack:"limit" bson:"-" mapstructure:"limit,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// The query in Prometheus format.
	Query string `json:"query" msgpack:"query" bson:"-" mapstructure:"query,omitempty"`

	// The result of the request.
	Result []map[string]string `json:"result" msgpack:"result" bson:"-" mapstructure:"result,omitempty"`

	// The start of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	Start string `json:"start,omitempty" msgpack:"start,omitempty" bson:"-" mapstructure:"start,omitempty"`

	// The relative start of the time window as time.Duration.
	StartRelative string `json:"startRelative,omitempty" msgpack:"startRelative,omitempty" bson:"-" mapstructure:"startRelative,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewMetricSerie returns a new *MetricSerie
func NewMetricSerie() *MetricSerie {

	return &MetricSerie{
		ModelVersion: 1,
		Limit:        100,
		Result:       []map[string]string{},
	}
}

// Identity returns the Identity of the object.
func (o *MetricSerie) Identity() elemental.Identity {

	return MetricSerieIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *MetricSerie) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *MetricSerie) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *MetricSerie) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesMetricSerie{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.Namespace = o.Namespace

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *MetricSerie) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesMetricSerie{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.Namespace = s.Namespace

	return nil
}

// Version returns the hardcoded version of the model.
func (o *MetricSerie) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *MetricSerie) BleveType() string {

	return "metricserie"
}

// DefaultOrder returns the list of default ordering fields.
func (o *MetricSerie) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *MetricSerie) Doc() string {

	return `This is a metric serie.`
}

func (o *MetricSerie) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetEnd returns the End of the receiver.
func (o *MetricSerie) GetEnd() string {

	return o.End
}

// SetEnd sets the property End of the receiver using the given value.
func (o *MetricSerie) SetEnd(end string) {

	o.End = end
}

// GetEndRelative returns the EndRelative of the receiver.
func (o *MetricSerie) GetEndRelative() string {

	return o.EndRelative
}

// GetNamespace returns the Namespace of the receiver.
func (o *MetricSerie) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *MetricSerie) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// GetStart returns the Start of the receiver.
func (o *MetricSerie) GetStart() string {

	return o.Start
}

// SetStart sets the property Start of the receiver using the given value.
func (o *MetricSerie) SetStart(start string) {

	o.Start = start
}

// GetStartRelative returns the StartRelative of the receiver.
func (o *MetricSerie) GetStartRelative() string {

	return o.StartRelative
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *MetricSerie) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseMetricSerie{
			ID:            &o.ID,
			End:           &o.End,
			EndRelative:   &o.EndRelative,
			Limit:         &o.Limit,
			Namespace:     &o.Namespace,
			Query:         &o.Query,
			Result:        &o.Result,
			Start:         &o.Start,
			StartRelative: &o.StartRelative,
		}
	}

	sp := &SparseMetricSerie{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "end":
			sp.End = &(o.End)
		case "endRelative":
			sp.EndRelative = &(o.EndRelative)
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

// Patch apply the non nil value of a *SparseMetricSerie to the object.
func (o *MetricSerie) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseMetricSerie)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.End != nil {
		o.End = *so.End
	}
	if so.EndRelative != nil {
		o.EndRelative = *so.EndRelative
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

// DeepCopy returns a deep copy if the MetricSerie.
func (o *MetricSerie) DeepCopy() *MetricSerie {

	if o == nil {
		return nil
	}

	out := &MetricSerie{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *MetricSerie.
func (o *MetricSerie) DeepCopyInto(out *MetricSerie) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy MetricSerie: %s", err))
	}

	*out = *target.(*MetricSerie)
}

// Validate valides the current information stored into the structure.
func (o *MetricSerie) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := ValidateDuration("endRelative", o.EndRelative); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("query", o.Query); err != nil {
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
func (*MetricSerie) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := MetricSerieAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return MetricSerieLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*MetricSerie) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return MetricSerieAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *MetricSerie) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "end":
		return o.End
	case "endRelative":
		return o.EndRelative
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

// MetricSerieAttributesMap represents the map of attribute for MetricSerie.
var MetricSerieAttributesMap = map[string]elemental.AttributeSpecification{
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
		Description:    `The query in Prometheus format.`,
		Exposed:        true,
		Name:           "query",
		Required:       true,
		Type:           "string",
	},
	"Result": {
		AllowedChoices: []string{},
		ConvertedName:  "Result",
		Description:    `The result of the request.`,
		Exposed:        true,
		Name:           "result",
		SubType:        "[]map[string]string",
		Type:           "external",
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

// MetricSerieLowerCaseAttributesMap represents the map of attribute for MetricSerie.
var MetricSerieLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
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
		Description:    `The query in Prometheus format.`,
		Exposed:        true,
		Name:           "query",
		Required:       true,
		Type:           "string",
	},
	"result": {
		AllowedChoices: []string{},
		ConvertedName:  "Result",
		Description:    `The result of the request.`,
		Exposed:        true,
		Name:           "result",
		SubType:        "[]map[string]string",
		Type:           "external",
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

// SparseMetricSeriesList represents a list of SparseMetricSeries
type SparseMetricSeriesList []*SparseMetricSerie

// Identity returns the identity of the objects in the list.
func (o SparseMetricSeriesList) Identity() elemental.Identity {

	return MetricSerieIdentity
}

// Copy returns a pointer to a copy the SparseMetricSeriesList.
func (o SparseMetricSeriesList) Copy() elemental.Identifiables {

	copy := append(SparseMetricSeriesList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseMetricSeriesList.
func (o SparseMetricSeriesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseMetricSeriesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseMetricSerie))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseMetricSeriesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseMetricSeriesList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseMetricSeriesList converted to MetricSeriesList.
func (o SparseMetricSeriesList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseMetricSeriesList) Version() int {

	return 1
}

// SparseMetricSerie represents the sparse version of a metricserie.
type SparseMetricSerie struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The end of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	End *string `json:"end,omitempty" msgpack:"end,omitempty" bson:"-" mapstructure:"end,omitempty"`

	// The relative end of the time window as time.Duration.
	EndRelative *string `json:"endRelative,omitempty" msgpack:"endRelative,omitempty" bson:"-" mapstructure:"endRelative,omitempty"`

	// The max number of results to return.
	Limit *int `json:"limit,omitempty" msgpack:"limit,omitempty" bson:"-" mapstructure:"limit,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// The query in Prometheus format.
	Query *string `json:"query,omitempty" msgpack:"query,omitempty" bson:"-" mapstructure:"query,omitempty"`

	// The result of the request.
	Result *[]map[string]string `json:"result,omitempty" msgpack:"result,omitempty" bson:"-" mapstructure:"result,omitempty"`

	// The start of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	Start *string `json:"start,omitempty" msgpack:"start,omitempty" bson:"-" mapstructure:"start,omitempty"`

	// The relative start of the time window as time.Duration.
	StartRelative *string `json:"startRelative,omitempty" msgpack:"startRelative,omitempty" bson:"-" mapstructure:"startRelative,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseMetricSerie returns a new  SparseMetricSerie.
func NewSparseMetricSerie() *SparseMetricSerie {
	return &SparseMetricSerie{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseMetricSerie) Identity() elemental.Identity {

	return MetricSerieIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseMetricSerie) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseMetricSerie) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseMetricSerie) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseMetricSerie{}

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
func (o *SparseMetricSerie) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseMetricSerie{}
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
func (o *SparseMetricSerie) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseMetricSerie) ToPlain() elemental.PlainIdentifiable {

	out := NewMetricSerie()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.End != nil {
		out.End = *o.End
	}
	if o.EndRelative != nil {
		out.EndRelative = *o.EndRelative
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
func (o *SparseMetricSerie) GetEnd() (out string) {

	if o.End == nil {
		return
	}

	return *o.End
}

// SetEnd sets the property End of the receiver using the address of the given value.
func (o *SparseMetricSerie) SetEnd(end string) {

	o.End = &end
}

// GetEndRelative returns the EndRelative of the receiver.
func (o *SparseMetricSerie) GetEndRelative() (out string) {

	if o.EndRelative == nil {
		return
	}

	return *o.EndRelative
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseMetricSerie) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseMetricSerie) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// GetStart returns the Start of the receiver.
func (o *SparseMetricSerie) GetStart() (out string) {

	if o.Start == nil {
		return
	}

	return *o.Start
}

// SetStart sets the property Start of the receiver using the address of the given value.
func (o *SparseMetricSerie) SetStart(start string) {

	o.Start = &start
}

// GetStartRelative returns the StartRelative of the receiver.
func (o *SparseMetricSerie) GetStartRelative() (out string) {

	if o.StartRelative == nil {
		return
	}

	return *o.StartRelative
}

// DeepCopy returns a deep copy if the SparseMetricSerie.
func (o *SparseMetricSerie) DeepCopy() *SparseMetricSerie {

	if o == nil {
		return nil
	}

	out := &SparseMetricSerie{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseMetricSerie.
func (o *SparseMetricSerie) DeepCopyInto(out *SparseMetricSerie) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseMetricSerie: %s", err))
	}

	*out = *target.(*SparseMetricSerie)
}

type mongoAttributesMetricSerie struct {
	ID        bson.ObjectId `bson:"_id,omitempty"`
	Namespace string        `bson:"namespace,omitempty"`
}
type mongoAttributesSparseMetricSerie struct {
	ID        bson.ObjectId `bson:"_id,omitempty"`
	Namespace *string       `bson:"namespace,omitempty"`
}
