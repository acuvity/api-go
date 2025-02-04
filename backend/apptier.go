// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// AppTierIdentity represents the Identity of the object.
var AppTierIdentity = elemental.Identity{
	Name:     "apptier",
	Category: "apptiers",
	Package:  "lain",
	Private:  false,
}

// AppTiersList represents a list of AppTiers
type AppTiersList []*AppTier

// Identity returns the identity of the objects in the list.
func (o AppTiersList) Identity() elemental.Identity {

	return AppTierIdentity
}

// Copy returns a pointer to a copy the AppTiersList.
func (o AppTiersList) Copy() elemental.Identifiables {

	out := append(AppTiersList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the AppTiersList.
func (o AppTiersList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(AppTiersList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*AppTier))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o AppTiersList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o AppTiersList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the AppTiersList converted to SparseAppTiersList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o AppTiersList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseAppTiersList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseAppTier)
	}

	return out
}

// Version returns the version of the content.
func (o AppTiersList) Version() int {

	return 1
}

// AppTier represents the model of a apptier
type AppTier struct {
	// The hostname.
	Name string `json:"name" msgpack:"name" bson:"name" mapstructure:"name,omitempty"`

	// A tag expression that identify an application tier based on downstream labels.
	Selector [][]string `json:"selector,omitempty" msgpack:"selector,omitempty" bson:"selector,omitempty" mapstructure:"selector,omitempty"`

	// The token for the current tier. Only populated by the backend when the caller's
	// claim match the parents app.subject.
	Token string `json:"token,omitempty" msgpack:"token,omitempty" bson:"-" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewAppTier returns a new *AppTier
func NewAppTier() *AppTier {

	return &AppTier{
		ModelVersion: 1,
		Selector:     [][]string{},
	}
}

// Identity returns the Identity of the object.
func (o *AppTier) Identity() elemental.Identity {

	return AppTierIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *AppTier) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *AppTier) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *AppTier) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesAppTier{}

	s.Name = o.Name
	s.Selector = o.Selector

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *AppTier) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesAppTier{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.Name = s.Name
	o.Selector = s.Selector

	return nil
}

// Version returns the hardcoded version of the model.
func (o *AppTier) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *AppTier) BleveType() string {

	return "apptier"
}

// DefaultOrder returns the list of default ordering fields.
func (o *AppTier) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *AppTier) Doc() string {

	return `Represents a particular tier of the application.`
}

func (o *AppTier) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *AppTier) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseAppTier{
			Name:     &o.Name,
			Selector: &o.Selector,
			Token:    &o.Token,
		}
	}

	sp := &SparseAppTier{}
	for _, f := range fields {
		switch f {
		case "name":
			sp.Name = &(o.Name)
		case "selector":
			sp.Selector = &(o.Selector)
		case "token":
			sp.Token = &(o.Token)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseAppTier to the object.
func (o *AppTier) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseAppTier)
	if so.Name != nil {
		o.Name = *so.Name
	}
	if so.Selector != nil {
		o.Selector = *so.Selector
	}
	if so.Token != nil {
		o.Token = *so.Token
	}
}

// DeepCopy returns a deep copy if the AppTier.
func (o *AppTier) DeepCopy() *AppTier {

	if o == nil {
		return nil
	}

	out := &AppTier{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *AppTier.
func (o *AppTier) DeepCopyInto(out *AppTier) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy AppTier: %s", err))
	}

	*out = *target.(*AppTier)
}

// Validate valides the current information stored into the structure.
func (o *AppTier) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("name", o.Name); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidateTagsExpression("selector", o.Selector); err != nil {
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
func (*AppTier) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := AppTierAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return AppTierLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*AppTier) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return AppTierAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *AppTier) ValueForAttribute(name string) any {

	switch name {
	case "name":
		return o.Name
	case "selector":
		return o.Selector
	case "token":
		return o.Token
	}

	return nil
}

// AppTierAttributesMap represents the map of attribute for AppTier.
var AppTierAttributesMap = map[string]elemental.AttributeSpecification{
	"Name": {
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		Description:    `The hostname.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"Selector": {
		AllowedChoices: []string{},
		BSONFieldName:  "selector",
		ConvertedName:  "Selector",
		Description:    `A tag expression that identify an application tier based on downstream labels.`,
		Exposed:        true,
		Name:           "selector",
		Stored:         true,
		SubType:        "[][]string",
		Type:           "external",
	},
	"Token": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		ConvertedName:  "Token",
		Description: `The token for the current tier. Only populated by the backend when the caller's
claim match the parents app.subject.`,
		Exposed:   true,
		Name:      "token",
		ReadOnly:  true,
		Transient: true,
		Type:      "string",
	},
}

// AppTierLowerCaseAttributesMap represents the map of attribute for AppTier.
var AppTierLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"name": {
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		Description:    `The hostname.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"selector": {
		AllowedChoices: []string{},
		BSONFieldName:  "selector",
		ConvertedName:  "Selector",
		Description:    `A tag expression that identify an application tier based on downstream labels.`,
		Exposed:        true,
		Name:           "selector",
		Stored:         true,
		SubType:        "[][]string",
		Type:           "external",
	},
	"token": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		ConvertedName:  "Token",
		Description: `The token for the current tier. Only populated by the backend when the caller's
claim match the parents app.subject.`,
		Exposed:   true,
		Name:      "token",
		ReadOnly:  true,
		Transient: true,
		Type:      "string",
	},
}

// SparseAppTiersList represents a list of SparseAppTiers
type SparseAppTiersList []*SparseAppTier

// Identity returns the identity of the objects in the list.
func (o SparseAppTiersList) Identity() elemental.Identity {

	return AppTierIdentity
}

// Copy returns a pointer to a copy the SparseAppTiersList.
func (o SparseAppTiersList) Copy() elemental.Identifiables {

	copy := append(SparseAppTiersList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseAppTiersList.
func (o SparseAppTiersList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseAppTiersList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseAppTier))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseAppTiersList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseAppTiersList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseAppTiersList converted to AppTiersList.
func (o SparseAppTiersList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseAppTiersList) Version() int {

	return 1
}

// SparseAppTier represents the sparse version of a apptier.
type SparseAppTier struct {
	// The hostname.
	Name *string `json:"name,omitempty" msgpack:"name,omitempty" bson:"name,omitempty" mapstructure:"name,omitempty"`

	// A tag expression that identify an application tier based on downstream labels.
	Selector *[][]string `json:"selector,omitempty" msgpack:"selector,omitempty" bson:"selector,omitempty" mapstructure:"selector,omitempty"`

	// The token for the current tier. Only populated by the backend when the caller's
	// claim match the parents app.subject.
	Token *string `json:"token,omitempty" msgpack:"token,omitempty" bson:"-" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseAppTier returns a new  SparseAppTier.
func NewSparseAppTier() *SparseAppTier {
	return &SparseAppTier{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseAppTier) Identity() elemental.Identity {

	return AppTierIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseAppTier) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseAppTier) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseAppTier) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseAppTier{}

	if o.Name != nil {
		s.Name = o.Name
	}
	if o.Selector != nil {
		s.Selector = o.Selector
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseAppTier) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseAppTier{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	if s.Name != nil {
		o.Name = s.Name
	}
	if s.Selector != nil {
		o.Selector = s.Selector
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseAppTier) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseAppTier) ToPlain() elemental.PlainIdentifiable {

	out := NewAppTier()
	if o.Name != nil {
		out.Name = *o.Name
	}
	if o.Selector != nil {
		out.Selector = *o.Selector
	}
	if o.Token != nil {
		out.Token = *o.Token
	}

	return out
}

// DeepCopy returns a deep copy if the SparseAppTier.
func (o *SparseAppTier) DeepCopy() *SparseAppTier {

	if o == nil {
		return nil
	}

	out := &SparseAppTier{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseAppTier.
func (o *SparseAppTier) DeepCopyInto(out *SparseAppTier) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseAppTier: %s", err))
	}

	*out = *target.(*SparseAppTier)
}

type mongoAttributesAppTier struct {
	Name     string     `bson:"name"`
	Selector [][]string `bson:"selector,omitempty"`
}
type mongoAttributesSparseAppTier struct {
	Name     *string     `bson:"name,omitempty"`
	Selector *[][]string `bson:"selector,omitempty"`
}
