// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// SerieIdentity represents the Identity of the object.
var SerieIdentity = elemental.Identity{
	Name:     "serie",
	Category: "series",
	Package:  "snitch",
	Private:  false,
}

// SeriesList represents a list of Series
type SeriesList []*Serie

// Identity returns the identity of the objects in the list.
func (o SeriesList) Identity() elemental.Identity {

	return SerieIdentity
}

// Copy returns a pointer to a copy the SeriesList.
func (o SeriesList) Copy() elemental.Identifiables {

	out := append(SeriesList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the SeriesList.
func (o SeriesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SeriesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*Serie))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SeriesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SeriesList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the SeriesList converted to SparseSeriesList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o SeriesList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseSeriesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseSerie)
	}

	return out
}

// Version returns the version of the content.
func (o SeriesList) Version() int {

	return 1
}

// Serie represents the model of a serie
type Serie struct {
	// ID is the identifier of the object.
	ID string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The end of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	End string `json:"end,omitempty" msgpack:"end,omitempty" bson:"-" mapstructure:"end,omitempty"`

	// The relative end of the time window as time.Duration.
	EndRelative string `json:"endRelative,omitempty" msgpack:"endRelative,omitempty" bson:"-" mapstructure:"endRelative,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// The query in LogQL format.
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

// NewSerie returns a new *Serie
func NewSerie() *Serie {

	return &Serie{
		ModelVersion: 1,
		Result:       []map[string]string{},
	}
}

// Identity returns the Identity of the object.
func (o *Serie) Identity() elemental.Identity {

	return SerieIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *Serie) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *Serie) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Serie) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSerie{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.Namespace = o.Namespace

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Serie) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSerie{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.Namespace = s.Namespace

	return nil
}

// Version returns the hardcoded version of the model.
func (o *Serie) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *Serie) BleveType() string {

	return "serie"
}

// DefaultOrder returns the list of default ordering fields.
func (o *Serie) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *Serie) Doc() string {

	return `This is a Log serie.`
}

func (o *Serie) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetNamespace returns the Namespace of the receiver.
func (o *Serie) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *Serie) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *Serie) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseSerie{
			ID:            &o.ID,
			End:           &o.End,
			EndRelative:   &o.EndRelative,
			Namespace:     &o.Namespace,
			Query:         &o.Query,
			Result:        &o.Result,
			Start:         &o.Start,
			StartRelative: &o.StartRelative,
		}
	}

	sp := &SparseSerie{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "end":
			sp.End = &(o.End)
		case "endRelative":
			sp.EndRelative = &(o.EndRelative)
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

// Patch apply the non nil value of a *SparseSerie to the object.
func (o *Serie) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseSerie)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.End != nil {
		o.End = *so.End
	}
	if so.EndRelative != nil {
		o.EndRelative = *so.EndRelative
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

// DeepCopy returns a deep copy if the Serie.
func (o *Serie) DeepCopy() *Serie {

	if o == nil {
		return nil
	}

	out := &Serie{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Serie.
func (o *Serie) DeepCopyInto(out *Serie) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Serie: %s", err))
	}

	*out = *target.(*Serie)
}

// Validate valides the current information stored into the structure.
func (o *Serie) Validate() error {

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
func (*Serie) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := SerieAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return SerieLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Serie) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return SerieAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Serie) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "end":
		return o.End
	case "endRelative":
		return o.EndRelative
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

// SerieAttributesMap represents the map of attribute for Serie.
var SerieAttributesMap = map[string]elemental.AttributeSpecification{
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
		Name:    "end",
		Type:    "string",
	},
	"EndRelative": {
		AllowedChoices: []string{},
		ConvertedName:  "EndRelative",
		Description:    `The relative end of the time window as time.Duration.`,
		Exposed:        true,
		Name:           "endRelative",
		Type:           "string",
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
		Description:    `The query in LogQL format.`,
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
		Name:    "start",
		Type:    "string",
	},
	"StartRelative": {
		AllowedChoices: []string{},
		ConvertedName:  "StartRelative",
		Description:    `The relative start of the time window as time.Duration.`,
		Exposed:        true,
		Name:           "startRelative",
		Type:           "string",
	},
}

// SerieLowerCaseAttributesMap represents the map of attribute for Serie.
var SerieLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
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
		Name:    "end",
		Type:    "string",
	},
	"endrelative": {
		AllowedChoices: []string{},
		ConvertedName:  "EndRelative",
		Description:    `The relative end of the time window as time.Duration.`,
		Exposed:        true,
		Name:           "endRelative",
		Type:           "string",
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
		Description:    `The query in LogQL format.`,
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
		Name:    "start",
		Type:    "string",
	},
	"startrelative": {
		AllowedChoices: []string{},
		ConvertedName:  "StartRelative",
		Description:    `The relative start of the time window as time.Duration.`,
		Exposed:        true,
		Name:           "startRelative",
		Type:           "string",
	},
}

// SparseSeriesList represents a list of SparseSeries
type SparseSeriesList []*SparseSerie

// Identity returns the identity of the objects in the list.
func (o SparseSeriesList) Identity() elemental.Identity {

	return SerieIdentity
}

// Copy returns a pointer to a copy the SparseSeriesList.
func (o SparseSeriesList) Copy() elemental.Identifiables {

	copy := append(SparseSeriesList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseSeriesList.
func (o SparseSeriesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseSeriesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseSerie))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseSeriesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseSeriesList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseSeriesList converted to SeriesList.
func (o SparseSeriesList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseSeriesList) Version() int {

	return 1
}

// SparseSerie represents the sparse version of a serie.
type SparseSerie struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The end of the time window in any format supported by
	// https://github.com/araddon/dateparse.
	End *string `json:"end,omitempty" msgpack:"end,omitempty" bson:"-" mapstructure:"end,omitempty"`

	// The relative end of the time window as time.Duration.
	EndRelative *string `json:"endRelative,omitempty" msgpack:"endRelative,omitempty" bson:"-" mapstructure:"endRelative,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// The query in LogQL format.
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

// NewSparseSerie returns a new  SparseSerie.
func NewSparseSerie() *SparseSerie {
	return &SparseSerie{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseSerie) Identity() elemental.Identity {

	return SerieIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseSerie) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseSerie) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseSerie) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseSerie{}

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
func (o *SparseSerie) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseSerie{}
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
func (o *SparseSerie) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseSerie) ToPlain() elemental.PlainIdentifiable {

	out := NewSerie()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.End != nil {
		out.End = *o.End
	}
	if o.EndRelative != nil {
		out.EndRelative = *o.EndRelative
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

// GetNamespace returns the Namespace of the receiver.
func (o *SparseSerie) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseSerie) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// DeepCopy returns a deep copy if the SparseSerie.
func (o *SparseSerie) DeepCopy() *SparseSerie {

	if o == nil {
		return nil
	}

	out := &SparseSerie{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseSerie.
func (o *SparseSerie) DeepCopyInto(out *SparseSerie) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseSerie: %s", err))
	}

	*out = *target.(*SparseSerie)
}

type mongoAttributesSerie struct {
	ID        bson.ObjectId `bson:"_id,omitempty"`
	Namespace string        `bson:"namespace,omitempty"`
}
type mongoAttributesSparseSerie struct {
	ID        bson.ObjectId `bson:"_id,omitempty"`
	Namespace *string       `bson:"namespace,omitempty"`
}
