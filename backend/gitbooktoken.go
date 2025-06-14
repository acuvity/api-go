// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"
	"slices"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// GitbookTokenIdentity represents the Identity of the object.
var GitbookTokenIdentity = elemental.Identity{
	Name:     "gitbooktoken",
	Category: "gitbooktokens",
	Package:  "amaterasu",
	Private:  false,
}

// GitbookTokensList represents a list of GitbookTokens
type GitbookTokensList []*GitbookToken

// Identity returns the identity of the objects in the list.
func (o GitbookTokensList) Identity() elemental.Identity {

	return GitbookTokenIdentity
}

// Copy returns a pointer to a copy the GitbookTokensList.
func (o GitbookTokensList) Copy() elemental.Identifiables {

	out := slices.Clone(o)
	return &out
}

// Append appends the objects to the a new copy of the GitbookTokensList.
func (o GitbookTokensList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*GitbookToken))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o GitbookTokensList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o GitbookTokensList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the GitbookTokensList converted to SparseGitbookTokensList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o GitbookTokensList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseGitbookTokensList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToSparse(fields...).(*SparseGitbookToken)
	}

	return out
}

// Version returns the version of the content.
func (o GitbookTokensList) Version() int {

	return 1
}

// GitbookToken represents the model of a gitbooktoken
type GitbookToken struct {
	// The token to access gitbook. This is not a valid acuvity token.
	Token string `json:"token,omitempty" msgpack:"token,omitempty" bson:"-" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewGitbookToken returns a new *GitbookToken
func NewGitbookToken() *GitbookToken {

	return &GitbookToken{
		ModelVersion: 1,
	}
}

// Identity returns the Identity of the object.
func (o *GitbookToken) Identity() elemental.Identity {

	return GitbookTokenIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *GitbookToken) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *GitbookToken) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *GitbookToken) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesGitbookToken{}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *GitbookToken) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesGitbookToken{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *GitbookToken) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *GitbookToken) BleveType() string {

	return "gitbooktoken"
}

// DefaultOrder returns the list of default ordering fields.
func (o *GitbookToken) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *GitbookToken) Doc() string {

	return `Allows to exchange an Acuvity token for a token signed for our documentation.`
}

func (o *GitbookToken) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *GitbookToken) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseGitbookToken{
			Token: &o.Token,
		}
	}

	sp := &SparseGitbookToken{}
	for _, f := range fields {
		switch f {
		case "token":
			sp.Token = &(o.Token)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseGitbookToken to the object.
func (o *GitbookToken) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseGitbookToken)
	if so.Token != nil {
		o.Token = *so.Token
	}
}

// DeepCopy returns a deep copy if the GitbookToken.
func (o *GitbookToken) DeepCopy() *GitbookToken {

	if o == nil {
		return nil
	}

	out := &GitbookToken{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *GitbookToken.
func (o *GitbookToken) DeepCopyInto(out *GitbookToken) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy GitbookToken: %s", err))
	}

	*out = *target.(*GitbookToken)
}

// Validate valides the current information stored into the structure.
func (o *GitbookToken) Validate() error {

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
func (*GitbookToken) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := GitbookTokenAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return GitbookTokenLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*GitbookToken) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return GitbookTokenAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *GitbookToken) ValueForAttribute(name string) any {

	switch name {
	case "token":
		return o.Token
	}

	return nil
}

// GitbookTokenAttributesMap represents the map of attribute for GitbookToken.
var GitbookTokenAttributesMap = map[string]elemental.AttributeSpecification{
	"Token": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		ConvertedName:  "Token",
		Description:    `The token to access gitbook. This is not a valid acuvity token.`,
		Exposed:        true,
		Name:           "token",
		ReadOnly:       true,
		Transient:      true,
		Type:           "string",
	},
}

// GitbookTokenLowerCaseAttributesMap represents the map of attribute for GitbookToken.
var GitbookTokenLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"token": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		ConvertedName:  "Token",
		Description:    `The token to access gitbook. This is not a valid acuvity token.`,
		Exposed:        true,
		Name:           "token",
		ReadOnly:       true,
		Transient:      true,
		Type:           "string",
	},
}

// SparseGitbookTokensList represents a list of SparseGitbookTokens
type SparseGitbookTokensList []*SparseGitbookToken

// Identity returns the identity of the objects in the list.
func (o SparseGitbookTokensList) Identity() elemental.Identity {

	return GitbookTokenIdentity
}

// Copy returns a pointer to a copy the SparseGitbookTokensList.
func (o SparseGitbookTokensList) Copy() elemental.Identifiables {

	copy := slices.Clone(o)
	return &copy
}

// Append appends the objects to the a new copy of the SparseGitbookTokensList.
func (o SparseGitbookTokensList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*SparseGitbookToken))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseGitbookTokensList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseGitbookTokensList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseGitbookTokensList converted to GitbookTokensList.
func (o SparseGitbookTokensList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseGitbookTokensList) Version() int {

	return 1
}

// SparseGitbookToken represents the sparse version of a gitbooktoken.
type SparseGitbookToken struct {
	// The token to access gitbook. This is not a valid acuvity token.
	Token *string `json:"token,omitempty" msgpack:"token,omitempty" bson:"-" mapstructure:"token,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseGitbookToken returns a new  SparseGitbookToken.
func NewSparseGitbookToken() *SparseGitbookToken {
	return &SparseGitbookToken{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseGitbookToken) Identity() elemental.Identity {

	return GitbookTokenIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseGitbookToken) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseGitbookToken) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseGitbookToken) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseGitbookToken{}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseGitbookToken) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseGitbookToken{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseGitbookToken) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseGitbookToken) ToPlain() elemental.PlainIdentifiable {

	out := NewGitbookToken()
	if o.Token != nil {
		out.Token = *o.Token
	}

	return out
}

// DeepCopy returns a deep copy if the SparseGitbookToken.
func (o *SparseGitbookToken) DeepCopy() *SparseGitbookToken {

	if o == nil {
		return nil
	}

	out := &SparseGitbookToken{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseGitbookToken.
func (o *SparseGitbookToken) DeepCopyInto(out *SparseGitbookToken) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseGitbookToken: %s", err))
	}

	*out = *target.(*SparseGitbookToken)
}

type mongoAttributesGitbookToken struct {
}
type mongoAttributesSparseGitbookToken struct {
}
