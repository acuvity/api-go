// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// SinkPagerDutyIdentity represents the Identity of the object.
var SinkPagerDutyIdentity = elemental.Identity{
	Name:     "sinkpagerduty",
	Category: "sinkpagerduty",
	Package:  "avi",
	Private:  false,
}

// SinkPagerDutiesList represents a list of SinkPagerDuties
type SinkPagerDutiesList []*SinkPagerDuty

// Identity returns the identity of the objects in the list.
func (o SinkPagerDutiesList) Identity() elemental.Identity {

	return SinkPagerDutyIdentity
}

// Copy returns a pointer to a copy the SinkPagerDutiesList.
func (o SinkPagerDutiesList) Copy() elemental.Identifiables {

	out := append(SinkPagerDutiesList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the SinkPagerDutiesList.
func (o SinkPagerDutiesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SinkPagerDutiesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SinkPagerDuty))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SinkPagerDutiesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SinkPagerDutiesList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the SinkPagerDutiesList converted to SparseSinkPagerDutiesList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o SinkPagerDutiesList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseSinkPagerDutiesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseSinkPagerDuty)
	}

	return out
}

// Version returns the version of the content.
func (o SinkPagerDutiesList) Version() int {

	return 1
}

// SinkPagerDuty represents the model of a sinkpagerduty
type SinkPagerDuty struct {
	// The token for PagerDuty events.
	Token string `json:"token" msgpack:"token" bson:"token" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSinkPagerDuty returns a new *SinkPagerDuty
func NewSinkPagerDuty() *SinkPagerDuty {

	return &SinkPagerDuty{
		ModelVersion: 1,
	}
}

// Identity returns the Identity of the object.
func (o *SinkPagerDuty) Identity() elemental.Identity {

	return SinkPagerDutyIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *SinkPagerDuty) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *SinkPagerDuty) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SinkPagerDuty) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSinkPagerDuty{}

	s.Token = o.Token

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SinkPagerDuty) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSinkPagerDuty{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.Token = s.Token

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SinkPagerDuty) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *SinkPagerDuty) BleveType() string {

	return "sinkpagerduty"
}

// DefaultOrder returns the list of default ordering fields.
func (o *SinkPagerDuty) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *SinkPagerDuty) Doc() string {

	return `Additional configuration for sending a PagerDuty event.`
}

func (o *SinkPagerDuty) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *SinkPagerDuty) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseSinkPagerDuty{
			Token: &o.Token,
		}
	}

	sp := &SparseSinkPagerDuty{}
	for _, f := range fields {
		switch f {
		case "token":
			sp.Token = &(o.Token)
		}
	}

	return sp
}

// EncryptAttributes encrypts the attributes marked as `encrypted` using the given encrypter.
func (o *SinkPagerDuty) EncryptAttributes(encrypter elemental.AttributeEncrypter) (err error) {

	if o.Token, err = encrypter.EncryptString(o.Token); err != nil {
		return fmt.Errorf("unable to encrypt attribute 'Token' for 'SinkPagerDuty' (%s): %s", o.Identifier(), err)
	}

	return nil
}

// DecryptAttributes decrypts the attributes marked as `encrypted` using the given decrypter.
func (o *SinkPagerDuty) DecryptAttributes(encrypter elemental.AttributeEncrypter) (err error) {

	if o.Token, err = encrypter.DecryptString(o.Token); err != nil {
		return fmt.Errorf("unable to decrypt attribute 'Token' for 'SinkPagerDuty' (%s): %s", o.Identifier(), err)
	}

	return nil
}

// Patch apply the non nil value of a *SparseSinkPagerDuty to the object.
func (o *SinkPagerDuty) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseSinkPagerDuty)
	if so.Token != nil {
		o.Token = *so.Token
	}
}

// DeepCopy returns a deep copy if the SinkPagerDuty.
func (o *SinkPagerDuty) DeepCopy() *SinkPagerDuty {

	if o == nil {
		return nil
	}

	out := &SinkPagerDuty{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SinkPagerDuty.
func (o *SinkPagerDuty) DeepCopyInto(out *SinkPagerDuty) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SinkPagerDuty: %s", err))
	}

	*out = *target.(*SinkPagerDuty)
}

// Validate valides the current information stored into the structure.
func (o *SinkPagerDuty) Validate() error {

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
func (*SinkPagerDuty) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := SinkPagerDutyAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return SinkPagerDutyLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*SinkPagerDuty) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return SinkPagerDutyAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *SinkPagerDuty) ValueForAttribute(name string) any {

	switch name {
	case "token":
		return o.Token
	}

	return nil
}

// SinkPagerDutyAttributesMap represents the map of attribute for SinkPagerDuty.
var SinkPagerDutyAttributesMap = map[string]elemental.AttributeSpecification{
	"Token": {
		AllowedChoices: []string{},
		BSONFieldName:  "token",
		ConvertedName:  "Token",
		Description:    `The token for PagerDuty events.`,
		Encrypted:      true,
		Exposed:        true,
		Name:           "token",
		Required:       true,
		Secret:         true,
		Stored:         true,
		Transient:      true,
		Type:           "string",
	},
}

// SinkPagerDutyLowerCaseAttributesMap represents the map of attribute for SinkPagerDuty.
var SinkPagerDutyLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"token": {
		AllowedChoices: []string{},
		BSONFieldName:  "token",
		ConvertedName:  "Token",
		Description:    `The token for PagerDuty events.`,
		Encrypted:      true,
		Exposed:        true,
		Name:           "token",
		Required:       true,
		Secret:         true,
		Stored:         true,
		Transient:      true,
		Type:           "string",
	},
}

// SparseSinkPagerDutiesList represents a list of SparseSinkPagerDuties
type SparseSinkPagerDutiesList []*SparseSinkPagerDuty

// Identity returns the identity of the objects in the list.
func (o SparseSinkPagerDutiesList) Identity() elemental.Identity {

	return SinkPagerDutyIdentity
}

// Copy returns a pointer to a copy the SparseSinkPagerDutiesList.
func (o SparseSinkPagerDutiesList) Copy() elemental.Identifiables {

	copy := append(SparseSinkPagerDutiesList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseSinkPagerDutiesList.
func (o SparseSinkPagerDutiesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseSinkPagerDutiesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseSinkPagerDuty))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseSinkPagerDutiesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseSinkPagerDutiesList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseSinkPagerDutiesList converted to SinkPagerDutiesList.
func (o SparseSinkPagerDutiesList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseSinkPagerDutiesList) Version() int {

	return 1
}

// SparseSinkPagerDuty represents the sparse version of a sinkpagerduty.
type SparseSinkPagerDuty struct {
	// The token for PagerDuty events.
	Token *string `json:"token,omitempty" msgpack:"token,omitempty" bson:"token,omitempty" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseSinkPagerDuty returns a new  SparseSinkPagerDuty.
func NewSparseSinkPagerDuty() *SparseSinkPagerDuty {
	return &SparseSinkPagerDuty{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseSinkPagerDuty) Identity() elemental.Identity {

	return SinkPagerDutyIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseSinkPagerDuty) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseSinkPagerDuty) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseSinkPagerDuty) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseSinkPagerDuty{}

	if o.Token != nil {
		s.Token = o.Token
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseSinkPagerDuty) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseSinkPagerDuty{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	if s.Token != nil {
		o.Token = s.Token
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseSinkPagerDuty) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseSinkPagerDuty) ToPlain() elemental.PlainIdentifiable {

	out := NewSinkPagerDuty()
	if o.Token != nil {
		out.Token = *o.Token
	}

	return out
}

// EncryptAttributes encrypts the attributes marked as `encrypted` using the given encrypter.
func (o *SparseSinkPagerDuty) EncryptAttributes(encrypter elemental.AttributeEncrypter) (err error) {

	if *o.Token, err = encrypter.EncryptString(*o.Token); err != nil {
		return fmt.Errorf("unable to encrypt attribute 'Token' for 'SparseSinkPagerDuty' (%s): %s", o.Identifier(), err)
	}

	return nil
}

// DecryptAttributes decrypts the attributes marked as `encrypted` using the given decrypter.
func (o *SparseSinkPagerDuty) DecryptAttributes(encrypter elemental.AttributeEncrypter) (err error) {

	if *o.Token, err = encrypter.DecryptString(*o.Token); err != nil {
		return fmt.Errorf("unable to decrypt attribute 'Token' for 'SparseSinkPagerDuty' (%s): %s", o.Identifier(), err)
	}

	return nil
}

// DeepCopy returns a deep copy if the SparseSinkPagerDuty.
func (o *SparseSinkPagerDuty) DeepCopy() *SparseSinkPagerDuty {

	if o == nil {
		return nil
	}

	out := &SparseSinkPagerDuty{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseSinkPagerDuty.
func (o *SparseSinkPagerDuty) DeepCopyInto(out *SparseSinkPagerDuty) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseSinkPagerDuty: %s", err))
	}

	*out = *target.(*SparseSinkPagerDuty)
}

type mongoAttributesSinkPagerDuty struct {
	Token string `bson:"token"`
}
type mongoAttributesSparseSinkPagerDuty struct {
	Token *string `bson:"token,omitempty"`
}
