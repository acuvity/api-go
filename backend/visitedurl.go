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

// VisitedURLOriginValue represents the possible values for attribute "origin".
type VisitedURLOriginValue string

const (
	// VisitedURLOriginProxy represents the value Proxy.
	VisitedURLOriginProxy VisitedURLOriginValue = "Proxy"

	// VisitedURLOriginWebExtension represents the value WebExtension.
	VisitedURLOriginWebExtension VisitedURLOriginValue = "WebExtension"
)

// VisitedURLIdentity represents the Identity of the object.
var VisitedURLIdentity = elemental.Identity{
	Name:     "visitedurl",
	Category: "visitedurls",
	Package:  "colektor",
	Private:  false,
}

// VisitedURLsList represents a list of VisitedURLs
type VisitedURLsList []*VisitedURL

// Identity returns the identity of the objects in the list.
func (o VisitedURLsList) Identity() elemental.Identity {

	return VisitedURLIdentity
}

// Copy returns a pointer to a copy the VisitedURLsList.
func (o VisitedURLsList) Copy() elemental.Identifiables {

	out := slices.Clone(o)
	return &out
}

// Append appends the objects to the a new copy of the VisitedURLsList.
func (o VisitedURLsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*VisitedURL))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o VisitedURLsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o VisitedURLsList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the VisitedURLsList converted to SparseVisitedURLsList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o VisitedURLsList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseVisitedURLsList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToSparse(fields...).(*SparseVisitedURL)
	}

	return out
}

// Version returns the version of the content.
func (o VisitedURLsList) Version() int {

	return 1
}

// VisitedURL represents the model of a visitedurl
type VisitedURL struct {
	// ID is the identifier of the object.
	ID string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Domain that has been visited.
	DomainHits []*DomainHits `json:"domainHits" msgpack:"domainHits" bson:"-" mapstructure:"domainHits,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// Origin indicates from where the url has been tracked.
	Origin VisitedURLOriginValue `json:"origin" msgpack:"origin" bson:"-" mapstructure:"origin,omitempty"`

	// The principal of the object.
	Principal *Principal `json:"principal" msgpack:"principal" bson:"principal" mapstructure:"principal,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewVisitedURL returns a new *VisitedURL
func NewVisitedURL() *VisitedURL {

	return &VisitedURL{
		ModelVersion: 1,
		Origin:       VisitedURLOriginProxy,
		Principal:    NewPrincipal(),
	}
}

// Identity returns the Identity of the object.
func (o *VisitedURL) Identity() elemental.Identity {

	return VisitedURLIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *VisitedURL) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *VisitedURL) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *VisitedURL) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesVisitedURL{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.ImportHash = o.ImportHash
	s.ImportLabel = o.ImportLabel
	s.Namespace = o.Namespace
	s.Principal = o.Principal

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *VisitedURL) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesVisitedURL{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.ImportHash = s.ImportHash
	o.ImportLabel = s.ImportLabel
	o.Namespace = s.Namespace
	o.Principal = s.Principal

	return nil
}

// Version returns the hardcoded version of the model.
func (o *VisitedURL) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *VisitedURL) BleveType() string {

	return "visitedurl"
}

// DefaultOrder returns the list of default ordering fields.
func (o *VisitedURL) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *VisitedURL) Doc() string {

	return `This is a visited URL.`
}

func (o *VisitedURL) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetImportHash returns the ImportHash of the receiver.
func (o *VisitedURL) GetImportHash() string {

	return o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the given value.
func (o *VisitedURL) SetImportHash(importHash string) {

	o.ImportHash = importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *VisitedURL) GetImportLabel() string {

	return o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the given value.
func (o *VisitedURL) SetImportLabel(importLabel string) {

	o.ImportLabel = importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *VisitedURL) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *VisitedURL) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *VisitedURL) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseVisitedURL{
			ID:          &o.ID,
			DomainHits:  &o.DomainHits,
			ImportHash:  &o.ImportHash,
			ImportLabel: &o.ImportLabel,
			Namespace:   &o.Namespace,
			Origin:      &o.Origin,
			Principal:   o.Principal,
		}
	}

	sp := &SparseVisitedURL{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "domainHits":
			sp.DomainHits = &(o.DomainHits)
		case "importHash":
			sp.ImportHash = &(o.ImportHash)
		case "importLabel":
			sp.ImportLabel = &(o.ImportLabel)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "origin":
			sp.Origin = &(o.Origin)
		case "principal":
			sp.Principal = o.Principal
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseVisitedURL to the object.
func (o *VisitedURL) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseVisitedURL)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.DomainHits != nil {
		o.DomainHits = *so.DomainHits
	}
	if so.ImportHash != nil {
		o.ImportHash = *so.ImportHash
	}
	if so.ImportLabel != nil {
		o.ImportLabel = *so.ImportLabel
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.Origin != nil {
		o.Origin = *so.Origin
	}
	if so.Principal != nil {
		o.Principal = so.Principal
	}
}

// DeepCopy returns a deep copy if the VisitedURL.
func (o *VisitedURL) DeepCopy() *VisitedURL {

	if o == nil {
		return nil
	}

	out := &VisitedURL{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *VisitedURL.
func (o *VisitedURL) DeepCopyInto(out *VisitedURL) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy VisitedURL: %s", err))
	}

	*out = *target.(*VisitedURL)
}

// Validate valides the current information stored into the structure.
func (o *VisitedURL) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	for _, sub := range o.DomainHits {
		if sub == nil {
			continue
		}
		elemental.ResetDefaultForZeroValues(sub)
		if err := sub.Validate(); err != nil {
			errors = errors.Append(err)
		}
	}

	if err := elemental.ValidateRequiredString("origin", string(o.Origin)); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidateStringInList("origin", string(o.Origin), []string{"WebExtension", "Proxy"}, false); err != nil {
		errors = errors.Append(err)
	}

	if o.Principal != nil {
		elemental.ResetDefaultForZeroValues(o.Principal)
		if err := o.Principal.Validate(); err != nil {
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
func (*VisitedURL) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := VisitedURLAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return VisitedURLLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*VisitedURL) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return VisitedURLAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *VisitedURL) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "domainHits":
		return o.DomainHits
	case "importHash":
		return o.ImportHash
	case "importLabel":
		return o.ImportLabel
	case "namespace":
		return o.Namespace
	case "origin":
		return o.Origin
	case "principal":
		return o.Principal
	}

	return nil
}

// VisitedURLAttributesMap represents the map of attribute for VisitedURL.
var VisitedURLAttributesMap = map[string]elemental.AttributeSpecification{
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
	"DomainHits": {
		AllowedChoices: []string{},
		ConvertedName:  "DomainHits",
		Description:    `Domain that has been visited.`,
		Exposed:        true,
		Name:           "domainHits",
		Required:       true,
		SubType:        "domainhits",
		Type:           "refList",
	},
	"ImportHash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "importhash",
		ConvertedName:  "ImportHash",
		CreationOnly:   true,
		Description:    `The hash of the structure used to compare with new import version.`,
		Exposed:        true,
		Getter:         true,
		Name:           "importHash",
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"ImportLabel": {
		AllowedChoices: []string{},
		BSONFieldName:  "importlabel",
		ConvertedName:  "ImportLabel",
		CreationOnly:   true,
		Description: `The user-defined import label that allows the system to group resources from the
same import operation.`,
		Exposed: true,
		Getter:  true,
		Name:    "importLabel",
		Setter:  true,
		Stored:  true,
		Type:    "string",
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
	"Origin": {
		AllowedChoices: []string{"WebExtension", "Proxy"},
		ConvertedName:  "Origin",
		DefaultValue:   VisitedURLOriginProxy,
		Description:    `Origin indicates from where the url has been tracked.`,
		Exposed:        true,
		Name:           "origin",
		Required:       true,
		Type:           "enum",
	},
	"Principal": {
		AllowedChoices: []string{},
		BSONFieldName:  "principal",
		ConvertedName:  "Principal",
		Description:    `The principal of the object.`,
		Exposed:        true,
		Name:           "principal",
		Required:       true,
		Stored:         true,
		SubType:        "principal",
		Type:           "ref",
	},
}

// VisitedURLLowerCaseAttributesMap represents the map of attribute for VisitedURL.
var VisitedURLLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
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
	"domainhits": {
		AllowedChoices: []string{},
		ConvertedName:  "DomainHits",
		Description:    `Domain that has been visited.`,
		Exposed:        true,
		Name:           "domainHits",
		Required:       true,
		SubType:        "domainhits",
		Type:           "refList",
	},
	"importhash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "importhash",
		ConvertedName:  "ImportHash",
		CreationOnly:   true,
		Description:    `The hash of the structure used to compare with new import version.`,
		Exposed:        true,
		Getter:         true,
		Name:           "importHash",
		Setter:         true,
		Stored:         true,
		Type:           "string",
	},
	"importlabel": {
		AllowedChoices: []string{},
		BSONFieldName:  "importlabel",
		ConvertedName:  "ImportLabel",
		CreationOnly:   true,
		Description: `The user-defined import label that allows the system to group resources from the
same import operation.`,
		Exposed: true,
		Getter:  true,
		Name:    "importLabel",
		Setter:  true,
		Stored:  true,
		Type:    "string",
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
	"origin": {
		AllowedChoices: []string{"WebExtension", "Proxy"},
		ConvertedName:  "Origin",
		DefaultValue:   VisitedURLOriginProxy,
		Description:    `Origin indicates from where the url has been tracked.`,
		Exposed:        true,
		Name:           "origin",
		Required:       true,
		Type:           "enum",
	},
	"principal": {
		AllowedChoices: []string{},
		BSONFieldName:  "principal",
		ConvertedName:  "Principal",
		Description:    `The principal of the object.`,
		Exposed:        true,
		Name:           "principal",
		Required:       true,
		Stored:         true,
		SubType:        "principal",
		Type:           "ref",
	},
}

// SparseVisitedURLsList represents a list of SparseVisitedURLs
type SparseVisitedURLsList []*SparseVisitedURL

// Identity returns the identity of the objects in the list.
func (o SparseVisitedURLsList) Identity() elemental.Identity {

	return VisitedURLIdentity
}

// Copy returns a pointer to a copy the SparseVisitedURLsList.
func (o SparseVisitedURLsList) Copy() elemental.Identifiables {

	copy := slices.Clone(o)
	return &copy
}

// Append appends the objects to the a new copy of the SparseVisitedURLsList.
func (o SparseVisitedURLsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := slices.Clone(o)
	for _, obj := range objects {
		out = append(out, obj.(*SparseVisitedURL))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseVisitedURLsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseVisitedURLsList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseVisitedURLsList converted to VisitedURLsList.
func (o SparseVisitedURLsList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := range len(o) {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseVisitedURLsList) Version() int {

	return 1
}

// SparseVisitedURL represents the sparse version of a visitedurl.
type SparseVisitedURL struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Domain that has been visited.
	DomainHits *[]*DomainHits `json:"domainHits,omitempty" msgpack:"domainHits,omitempty" bson:"-" mapstructure:"domainHits,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash *string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel *string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// Origin indicates from where the url has been tracked.
	Origin *VisitedURLOriginValue `json:"origin,omitempty" msgpack:"origin,omitempty" bson:"-" mapstructure:"origin,omitempty"`

	// The principal of the object.
	Principal *Principal `json:"principal,omitempty" msgpack:"principal,omitempty" bson:"principal,omitempty" mapstructure:"principal,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseVisitedURL returns a new  SparseVisitedURL.
func NewSparseVisitedURL() *SparseVisitedURL {
	return &SparseVisitedURL{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseVisitedURL) Identity() elemental.Identity {

	return VisitedURLIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseVisitedURL) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseVisitedURL) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseVisitedURL) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseVisitedURL{}

	if o.ID != nil {
		s.ID = bson.ObjectIdHex(*o.ID)
	}
	if o.ImportHash != nil {
		s.ImportHash = o.ImportHash
	}
	if o.ImportLabel != nil {
		s.ImportLabel = o.ImportLabel
	}
	if o.Namespace != nil {
		s.Namespace = o.Namespace
	}
	if o.Principal != nil {
		s.Principal = o.Principal
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseVisitedURL) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseVisitedURL{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	id := s.ID.Hex()
	o.ID = &id
	if s.ImportHash != nil {
		o.ImportHash = s.ImportHash
	}
	if s.ImportLabel != nil {
		o.ImportLabel = s.ImportLabel
	}
	if s.Namespace != nil {
		o.Namespace = s.Namespace
	}
	if s.Principal != nil {
		o.Principal = s.Principal
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseVisitedURL) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseVisitedURL) ToPlain() elemental.PlainIdentifiable {

	out := NewVisitedURL()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.DomainHits != nil {
		out.DomainHits = *o.DomainHits
	}
	if o.ImportHash != nil {
		out.ImportHash = *o.ImportHash
	}
	if o.ImportLabel != nil {
		out.ImportLabel = *o.ImportLabel
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.Origin != nil {
		out.Origin = *o.Origin
	}
	if o.Principal != nil {
		out.Principal = o.Principal
	}

	return out
}

// GetImportHash returns the ImportHash of the receiver.
func (o *SparseVisitedURL) GetImportHash() (out string) {

	if o.ImportHash == nil {
		return
	}

	return *o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the address of the given value.
func (o *SparseVisitedURL) SetImportHash(importHash string) {

	o.ImportHash = &importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *SparseVisitedURL) GetImportLabel() (out string) {

	if o.ImportLabel == nil {
		return
	}

	return *o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the address of the given value.
func (o *SparseVisitedURL) SetImportLabel(importLabel string) {

	o.ImportLabel = &importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseVisitedURL) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseVisitedURL) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// DeepCopy returns a deep copy if the SparseVisitedURL.
func (o *SparseVisitedURL) DeepCopy() *SparseVisitedURL {

	if o == nil {
		return nil
	}

	out := &SparseVisitedURL{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseVisitedURL.
func (o *SparseVisitedURL) DeepCopyInto(out *SparseVisitedURL) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseVisitedURL: %s", err))
	}

	*out = *target.(*SparseVisitedURL)
}

type mongoAttributesVisitedURL struct {
	ID          bson.ObjectId `bson:"_id,omitempty"`
	ImportHash  string        `bson:"importhash,omitempty"`
	ImportLabel string        `bson:"importlabel,omitempty"`
	Namespace   string        `bson:"namespace,omitempty"`
	Principal   *Principal    `bson:"principal"`
}
type mongoAttributesSparseVisitedURL struct {
	ID          bson.ObjectId `bson:"_id,omitempty"`
	ImportHash  *string       `bson:"importhash,omitempty"`
	ImportLabel *string       `bson:"importlabel,omitempty"`
	Namespace   *string       `bson:"namespace,omitempty"`
	Principal   *Principal    `bson:"principal,omitempty"`
}
