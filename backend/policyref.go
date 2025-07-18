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

// PolicyRefIdentity represents the Identity of the object.
var PolicyRefIdentity = elemental.Identity{
	Name:     "policyref",
	Category: "policyrefs",
	Package:  "colektor",
	Private:  false,
}

// PolicyRefsList represents a list of PolicyRefs
type PolicyRefsList []*PolicyRef

// Identity returns the identity of the objects in the list.
func (o PolicyRefsList) Identity() elemental.Identity {

	return PolicyRefIdentity
}

// Copy returns a pointer to a copy the PolicyRefsList.
func (o PolicyRefsList) Copy() elemental.Identifiables {

	out := slices.Clone(o)
	return &out
}

// Append appends the objects to the a new copy of the PolicyRefsList.
func (o PolicyRefsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*PolicyRef))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o PolicyRefsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o PolicyRefsList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the PolicyRefsList converted to SparsePolicyRefsList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o PolicyRefsList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparsePolicyRefsList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToSparse(fields...).(*SparsePolicyRef)
	}

	return out
}

// Version returns the version of the content.
func (o PolicyRefsList) Version() int {

	return 1
}

// PolicyRef represents the model of a policyref
type PolicyRef struct {
	// Teams that were used to trigger this policy.
	MatchingTeams []string `json:"matchingTeams,omitempty" msgpack:"matchingTeams,omitempty" bson:"matchingteams,omitempty" mapstructure:"matchingTeams,omitempty"`

	// The ID of the referenced policy.
	PolicyID string `json:"policyID" msgpack:"policyID" bson:"policyid" mapstructure:"policyID,omitempty"`

	// The identity name of the referenced policy.
	PolicyIdentity string `json:"policyIdentity" msgpack:"policyIdentity" bson:"policyidentity" mapstructure:"policyIdentity,omitempty"`

	// The name of the referenced policy.
	PolicyName string `json:"policyName" msgpack:"policyName" bson:"policyname" mapstructure:"policyName,omitempty"`

	// The namespace of the referenced policy.
	PolicyNamespace string `json:"policyNamespace" msgpack:"policyNamespace" bson:"policynamespace" mapstructure:"policyNamespace,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewPolicyRef returns a new *PolicyRef
func NewPolicyRef() *PolicyRef {

	return &PolicyRef{
		ModelVersion:  1,
		MatchingTeams: []string{},
	}
}

// Identity returns the Identity of the object.
func (o *PolicyRef) Identity() elemental.Identity {

	return PolicyRefIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *PolicyRef) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *PolicyRef) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *PolicyRef) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesPolicyRef{}

	s.MatchingTeams = o.MatchingTeams
	s.PolicyID = o.PolicyID
	s.PolicyIdentity = o.PolicyIdentity
	s.PolicyName = o.PolicyName
	s.PolicyNamespace = o.PolicyNamespace

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *PolicyRef) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesPolicyRef{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.MatchingTeams = s.MatchingTeams
	o.PolicyID = s.PolicyID
	o.PolicyIdentity = s.PolicyIdentity
	o.PolicyName = s.PolicyName
	o.PolicyNamespace = s.PolicyNamespace

	return nil
}

// Version returns the hardcoded version of the model.
func (o *PolicyRef) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *PolicyRef) BleveType() string {

	return "policyref"
}

// DefaultOrder returns the list of default ordering fields.
func (o *PolicyRef) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *PolicyRef) Doc() string {

	return `Reference a policy.`
}

func (o *PolicyRef) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *PolicyRef) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparsePolicyRef{
			MatchingTeams:   &o.MatchingTeams,
			PolicyID:        &o.PolicyID,
			PolicyIdentity:  &o.PolicyIdentity,
			PolicyName:      &o.PolicyName,
			PolicyNamespace: &o.PolicyNamespace,
		}
	}

	sp := &SparsePolicyRef{}
	for _, f := range fields {
		switch f {
		case "matchingTeams":
			sp.MatchingTeams = &(o.MatchingTeams)
		case "policyID":
			sp.PolicyID = &(o.PolicyID)
		case "policyIdentity":
			sp.PolicyIdentity = &(o.PolicyIdentity)
		case "policyName":
			sp.PolicyName = &(o.PolicyName)
		case "policyNamespace":
			sp.PolicyNamespace = &(o.PolicyNamespace)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparsePolicyRef to the object.
func (o *PolicyRef) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparsePolicyRef)
	if so.MatchingTeams != nil {
		o.MatchingTeams = *so.MatchingTeams
	}
	if so.PolicyID != nil {
		o.PolicyID = *so.PolicyID
	}
	if so.PolicyIdentity != nil {
		o.PolicyIdentity = *so.PolicyIdentity
	}
	if so.PolicyName != nil {
		o.PolicyName = *so.PolicyName
	}
	if so.PolicyNamespace != nil {
		o.PolicyNamespace = *so.PolicyNamespace
	}
}

// DeepCopy returns a deep copy if the PolicyRef.
func (o *PolicyRef) DeepCopy() *PolicyRef {

	if o == nil {
		return nil
	}

	out := &PolicyRef{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *PolicyRef.
func (o *PolicyRef) DeepCopyInto(out *PolicyRef) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy PolicyRef: %s", err))
	}

	*out = *target.(*PolicyRef)
}

// Validate valides the current information stored into the structure.
func (o *PolicyRef) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("policyID", o.PolicyID); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateRequiredString("policyIdentity", o.PolicyIdentity); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateRequiredString("policyName", o.PolicyName); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateRequiredString("policyNamespace", o.PolicyNamespace); err != nil {
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
func (*PolicyRef) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := PolicyRefAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return PolicyRefLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*PolicyRef) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return PolicyRefAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *PolicyRef) ValueForAttribute(name string) any {

	switch name {
	case "matchingTeams":
		return o.MatchingTeams
	case "policyID":
		return o.PolicyID
	case "policyIdentity":
		return o.PolicyIdentity
	case "policyName":
		return o.PolicyName
	case "policyNamespace":
		return o.PolicyNamespace
	}

	return nil
}

// PolicyRefAttributesMap represents the map of attribute for PolicyRef.
var PolicyRefAttributesMap = map[string]elemental.AttributeSpecification{
	"MatchingTeams": {
		AllowedChoices: []string{},
		BSONFieldName:  "matchingteams",
		ConvertedName:  "MatchingTeams",
		Description:    `Teams that were used to trigger this policy.`,
		Exposed:        true,
		Name:           "matchingTeams",
		Stored:         true,
		SubType:        "string",
		Type:           "list",
	},
	"PolicyID": {
		AllowedChoices: []string{},
		BSONFieldName:  "policyid",
		ConvertedName:  "PolicyID",
		Description:    `The ID of the referenced policy.`,
		Exposed:        true,
		Name:           "policyID",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"PolicyIdentity": {
		AllowedChoices: []string{},
		BSONFieldName:  "policyidentity",
		ConvertedName:  "PolicyIdentity",
		Description:    `The identity name of the referenced policy.`,
		Exposed:        true,
		Name:           "policyIdentity",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"PolicyName": {
		AllowedChoices: []string{},
		BSONFieldName:  "policyname",
		ConvertedName:  "PolicyName",
		Description:    `The name of the referenced policy.`,
		Exposed:        true,
		Name:           "policyName",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"PolicyNamespace": {
		AllowedChoices: []string{},
		BSONFieldName:  "policynamespace",
		ConvertedName:  "PolicyNamespace",
		Description:    `The namespace of the referenced policy.`,
		Exposed:        true,
		Name:           "policyNamespace",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
}

// PolicyRefLowerCaseAttributesMap represents the map of attribute for PolicyRef.
var PolicyRefLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
	"matchingteams": {
		AllowedChoices: []string{},
		BSONFieldName:  "matchingteams",
		ConvertedName:  "MatchingTeams",
		Description:    `Teams that were used to trigger this policy.`,
		Exposed:        true,
		Name:           "matchingTeams",
		Stored:         true,
		SubType:        "string",
		Type:           "list",
	},
	"policyid": {
		AllowedChoices: []string{},
		BSONFieldName:  "policyid",
		ConvertedName:  "PolicyID",
		Description:    `The ID of the referenced policy.`,
		Exposed:        true,
		Name:           "policyID",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"policyidentity": {
		AllowedChoices: []string{},
		BSONFieldName:  "policyidentity",
		ConvertedName:  "PolicyIdentity",
		Description:    `The identity name of the referenced policy.`,
		Exposed:        true,
		Name:           "policyIdentity",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"policyname": {
		AllowedChoices: []string{},
		BSONFieldName:  "policyname",
		ConvertedName:  "PolicyName",
		Description:    `The name of the referenced policy.`,
		Exposed:        true,
		Name:           "policyName",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
	"policynamespace": {
		AllowedChoices: []string{},
		BSONFieldName:  "policynamespace",
		ConvertedName:  "PolicyNamespace",
		Description:    `The namespace of the referenced policy.`,
		Exposed:        true,
		Name:           "policyNamespace",
		Required:       true,
		Stored:         true,
		Type:           "string",
	},
}

// SparsePolicyRefsList represents a list of SparsePolicyRefs
type SparsePolicyRefsList []*SparsePolicyRef

// Identity returns the identity of the objects in the list.
func (o SparsePolicyRefsList) Identity() elemental.Identity {

	return PolicyRefIdentity
}

// Copy returns a pointer to a copy the SparsePolicyRefsList.
func (o SparsePolicyRefsList) Copy() elemental.Identifiables {

	copy := slices.Clone(o)
	return &copy
}

// Append appends the objects to the a new copy of the SparsePolicyRefsList.
func (o SparsePolicyRefsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*SparsePolicyRef))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparsePolicyRefsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparsePolicyRefsList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparsePolicyRefsList converted to PolicyRefsList.
func (o SparsePolicyRefsList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparsePolicyRefsList) Version() int {

	return 1
}

// SparsePolicyRef represents the sparse version of a policyref.
type SparsePolicyRef struct {
	// Teams that were used to trigger this policy.
	MatchingTeams *[]string `json:"matchingTeams,omitempty" msgpack:"matchingTeams,omitempty" bson:"matchingteams,omitempty" mapstructure:"matchingTeams,omitempty"`

	// The ID of the referenced policy.
	PolicyID *string `json:"policyID,omitempty" msgpack:"policyID,omitempty" bson:"policyid,omitempty" mapstructure:"policyID,omitempty"`

	// The identity name of the referenced policy.
	PolicyIdentity *string `json:"policyIdentity,omitempty" msgpack:"policyIdentity,omitempty" bson:"policyidentity,omitempty" mapstructure:"policyIdentity,omitempty"`

	// The name of the referenced policy.
	PolicyName *string `json:"policyName,omitempty" msgpack:"policyName,omitempty" bson:"policyname,omitempty" mapstructure:"policyName,omitempty"`

	// The namespace of the referenced policy.
	PolicyNamespace *string `json:"policyNamespace,omitempty" msgpack:"policyNamespace,omitempty" bson:"policynamespace,omitempty" mapstructure:"policyNamespace,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparsePolicyRef returns a new  SparsePolicyRef.
func NewSparsePolicyRef() *SparsePolicyRef {
	return &SparsePolicyRef{}
}

// Identity returns the Identity of the sparse object.
func (o *SparsePolicyRef) Identity() elemental.Identity {

	return PolicyRefIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparsePolicyRef) Identifier() string {

	return ""
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparsePolicyRef) SetIdentifier(id string) {

}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparsePolicyRef) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparsePolicyRef{}

	if o.MatchingTeams != nil {
		s.MatchingTeams = o.MatchingTeams
	}
	if o.PolicyID != nil {
		s.PolicyID = o.PolicyID
	}
	if o.PolicyIdentity != nil {
		s.PolicyIdentity = o.PolicyIdentity
	}
	if o.PolicyName != nil {
		s.PolicyName = o.PolicyName
	}
	if o.PolicyNamespace != nil {
		s.PolicyNamespace = o.PolicyNamespace
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparsePolicyRef) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparsePolicyRef{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	if s.MatchingTeams != nil {
		o.MatchingTeams = s.MatchingTeams
	}
	if s.PolicyID != nil {
		o.PolicyID = s.PolicyID
	}
	if s.PolicyIdentity != nil {
		o.PolicyIdentity = s.PolicyIdentity
	}
	if s.PolicyName != nil {
		o.PolicyName = s.PolicyName
	}
	if s.PolicyNamespace != nil {
		o.PolicyNamespace = s.PolicyNamespace
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparsePolicyRef) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparsePolicyRef) ToPlain() elemental.PlainIdentifiable {

	out := NewPolicyRef()
	if o.MatchingTeams != nil {
		out.MatchingTeams = *o.MatchingTeams
	}
	if o.PolicyID != nil {
		out.PolicyID = *o.PolicyID
	}
	if o.PolicyIdentity != nil {
		out.PolicyIdentity = *o.PolicyIdentity
	}
	if o.PolicyName != nil {
		out.PolicyName = *o.PolicyName
	}
	if o.PolicyNamespace != nil {
		out.PolicyNamespace = *o.PolicyNamespace
	}

	return out
}

// DeepCopy returns a deep copy if the SparsePolicyRef.
func (o *SparsePolicyRef) DeepCopy() *SparsePolicyRef {

	if o == nil {
		return nil
	}

	out := &SparsePolicyRef{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparsePolicyRef.
func (o *SparsePolicyRef) DeepCopyInto(out *SparsePolicyRef) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparsePolicyRef: %s", err))
	}

	*out = *target.(*SparsePolicyRef)
}

type mongoAttributesPolicyRef struct {
	MatchingTeams   []string `bson:"matchingteams,omitempty"`
	PolicyID        string   `bson:"policyid"`
	PolicyIdentity  string   `bson:"policyidentity"`
	PolicyName      string   `bson:"policyname"`
	PolicyNamespace string   `bson:"policynamespace"`
}
type mongoAttributesSparsePolicyRef struct {
	MatchingTeams   *[]string `bson:"matchingteams,omitempty"`
	PolicyID        *string   `bson:"policyid,omitempty"`
	PolicyIdentity  *string   `bson:"policyidentity,omitempty"`
	PolicyName      *string   `bson:"policyname,omitempty"`
	PolicyNamespace *string   `bson:"policynamespace,omitempty"`
}
