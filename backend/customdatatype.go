// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/model.gotpl)

package api

import (
	"fmt"
	"time"

	"github.com/globalsign/mgo/bson"
	"github.com/mitchellh/copystructure"
	"go.acuvity.ai/elemental"
)

// CustomDataTypeIdentity represents the Identity of the object.
var CustomDataTypeIdentity = elemental.Identity{
	Name:     "customdatatype",
	Category: "customdatatypes",
	Package:  "lain",
	Private:  false,
}

// CustomDataTypesList represents a list of CustomDataTypes
type CustomDataTypesList []*CustomDataType

// Identity returns the identity of the objects in the list.
func (o CustomDataTypesList) Identity() elemental.Identity {

	return CustomDataTypeIdentity
}

// Copy returns a pointer to a copy the CustomDataTypesList.
func (o CustomDataTypesList) Copy() elemental.Identifiables {

	out := append(CustomDataTypesList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the CustomDataTypesList.
func (o CustomDataTypesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(CustomDataTypesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*CustomDataType))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o CustomDataTypesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o CustomDataTypesList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the CustomDataTypesList converted to SparseCustomDataTypesList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o CustomDataTypesList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseCustomDataTypesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseCustomDataType)
	}

	return out
}

// Version returns the version of the content.
func (o CustomDataTypesList) Version() int {

	return 1
}

// CustomDataType represents the model of a customdatatype
type CustomDataType struct {
	// ID is the identifier of the object.
	ID string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime time.Time `json:"createTime" msgpack:"createTime" bson:"createtime" mapstructure:"createTime,omitempty"`

	// Description of the custom data type.
	Description string `json:"description" msgpack:"description" bson:"description" mapstructure:"description,omitempty"`

	// Friendly name of the object.
	FriendlyName string `json:"friendlyName" msgpack:"friendlyName" bson:"friendlyname" mapstructure:"friendlyName,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// A list of RE2 regular expressions used for data detection. Each expression can
	// include zero or one capturing group. If no capturing group is present, detection
	// positions will be determined based on the entire captured portion of the data.
	// If a single capturing group is included, the detection positions will correspond
	// to the part defined by that group. However, if more than one capturing group is
	// found, the system will return a validation error. Additionally, extra
	// validations are performed to ensure that the regular expressions are not overly
	// complex, preventing any negative impact on detection engine performance.
	Matches []string `json:"matches" msgpack:"matches" bson:"matches" mapstructure:"matches,omitempty"`

	// The internal reference name of the object. It is a sanitized version of Friendly
	// Name if empty.
	Name string `json:"name" msgpack:"name" bson:"name" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// Propagates the object to all child namespaces. This is always true.
	Propagate bool `json:"propagate" msgpack:"propagate" bson:"propagate" mapstructure:"propagate,omitempty"`

	// Last update date of the object.
	UpdateTime time.Time `json:"updateTime" msgpack:"updateTime" bson:"updatetime" mapstructure:"updateTime,omitempty"`

	// Hash of the object used to shard the data.
	ZHash int `json:"-" msgpack:"-" bson:"zhash" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone int `json:"-" msgpack:"-" bson:"zone" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewCustomDataType returns a new *CustomDataType
func NewCustomDataType() *CustomDataType {

	return &CustomDataType{
		ModelVersion: 1,
		Matches:      []string{},
		Propagate:    true,
	}
}

// Identity returns the Identity of the object.
func (o *CustomDataType) Identity() elemental.Identity {

	return CustomDataTypeIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *CustomDataType) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *CustomDataType) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *CustomDataType) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesCustomDataType{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.CreateTime = o.CreateTime
	s.Description = o.Description
	s.FriendlyName = o.FriendlyName
	s.ImportHash = o.ImportHash
	s.ImportLabel = o.ImportLabel
	s.Matches = o.Matches
	s.Name = o.Name
	s.Namespace = o.Namespace
	s.Propagate = o.Propagate
	s.UpdateTime = o.UpdateTime
	s.ZHash = o.ZHash
	s.Zone = o.Zone

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *CustomDataType) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesCustomDataType{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.CreateTime = s.CreateTime
	o.Description = s.Description
	o.FriendlyName = s.FriendlyName
	o.ImportHash = s.ImportHash
	o.ImportLabel = s.ImportLabel
	o.Matches = s.Matches
	o.Name = s.Name
	o.Namespace = s.Namespace
	o.Propagate = s.Propagate
	o.UpdateTime = s.UpdateTime
	o.ZHash = s.ZHash
	o.Zone = s.Zone

	return nil
}

// Version returns the hardcoded version of the model.
func (o *CustomDataType) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *CustomDataType) BleveType() string {

	return "customdatatype"
}

// DefaultOrder returns the list of default ordering fields.
func (o *CustomDataType) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *CustomDataType) Doc() string {

	return `Allows to create custom data detectors.`
}

func (o *CustomDataType) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *CustomDataType) GetCreateTime() time.Time {

	return o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the given value.
func (o *CustomDataType) SetCreateTime(createTime time.Time) {

	o.CreateTime = createTime
}

// GetImportHash returns the ImportHash of the receiver.
func (o *CustomDataType) GetImportHash() string {

	return o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the given value.
func (o *CustomDataType) SetImportHash(importHash string) {

	o.ImportHash = importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *CustomDataType) GetImportLabel() string {

	return o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the given value.
func (o *CustomDataType) SetImportLabel(importLabel string) {

	o.ImportLabel = importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *CustomDataType) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *CustomDataType) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// GetPropagate returns the Propagate of the receiver.
func (o *CustomDataType) GetPropagate() bool {

	return o.Propagate
}

// SetPropagate sets the property Propagate of the receiver using the given value.
func (o *CustomDataType) SetPropagate(propagate bool) {

	o.Propagate = propagate
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *CustomDataType) GetUpdateTime() time.Time {

	return o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the given value.
func (o *CustomDataType) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = updateTime
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *CustomDataType) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseCustomDataType{
			ID:           &o.ID,
			CreateTime:   &o.CreateTime,
			Description:  &o.Description,
			FriendlyName: &o.FriendlyName,
			ImportHash:   &o.ImportHash,
			ImportLabel:  &o.ImportLabel,
			Matches:      &o.Matches,
			Name:         &o.Name,
			Namespace:    &o.Namespace,
			Propagate:    &o.Propagate,
			UpdateTime:   &o.UpdateTime,
			ZHash:        &o.ZHash,
			Zone:         &o.Zone,
		}
	}

	sp := &SparseCustomDataType{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "createTime":
			sp.CreateTime = &(o.CreateTime)
		case "description":
			sp.Description = &(o.Description)
		case "friendlyName":
			sp.FriendlyName = &(o.FriendlyName)
		case "importHash":
			sp.ImportHash = &(o.ImportHash)
		case "importLabel":
			sp.ImportLabel = &(o.ImportLabel)
		case "matches":
			sp.Matches = &(o.Matches)
		case "name":
			sp.Name = &(o.Name)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "propagate":
			sp.Propagate = &(o.Propagate)
		case "updateTime":
			sp.UpdateTime = &(o.UpdateTime)
		case "zHash":
			sp.ZHash = &(o.ZHash)
		case "zone":
			sp.Zone = &(o.Zone)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseCustomDataType to the object.
func (o *CustomDataType) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseCustomDataType)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.CreateTime != nil {
		o.CreateTime = *so.CreateTime
	}
	if so.Description != nil {
		o.Description = *so.Description
	}
	if so.FriendlyName != nil {
		o.FriendlyName = *so.FriendlyName
	}
	if so.ImportHash != nil {
		o.ImportHash = *so.ImportHash
	}
	if so.ImportLabel != nil {
		o.ImportLabel = *so.ImportLabel
	}
	if so.Matches != nil {
		o.Matches = *so.Matches
	}
	if so.Name != nil {
		o.Name = *so.Name
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.Propagate != nil {
		o.Propagate = *so.Propagate
	}
	if so.UpdateTime != nil {
		o.UpdateTime = *so.UpdateTime
	}
	if so.ZHash != nil {
		o.ZHash = *so.ZHash
	}
	if so.Zone != nil {
		o.Zone = *so.Zone
	}
}

// DeepCopy returns a deep copy if the CustomDataType.
func (o *CustomDataType) DeepCopy() *CustomDataType {

	if o == nil {
		return nil
	}

	out := &CustomDataType{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *CustomDataType.
func (o *CustomDataType) DeepCopyInto(out *CustomDataType) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy CustomDataType: %s", err))
	}

	*out = *target.(*CustomDataType)
}

// Validate valides the current information stored into the structure.
func (o *CustomDataType) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("friendlyName", o.FriendlyName); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidateFriendlyName("friendlyName", o.FriendlyName); err != nil {
		errors = errors.Append(err)
	}

	if err := ValidateRegexps("matches", o.Matches); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidatePattern("name", o.Name, `^[a-zA-Z0-9-_]+$`, `must only contain alpha numerical characters, '-' or '_'.`, false); err != nil {
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
func (*CustomDataType) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := CustomDataTypeAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return CustomDataTypeLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*CustomDataType) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return CustomDataTypeAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *CustomDataType) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "createTime":
		return o.CreateTime
	case "description":
		return o.Description
	case "friendlyName":
		return o.FriendlyName
	case "importHash":
		return o.ImportHash
	case "importLabel":
		return o.ImportLabel
	case "matches":
		return o.Matches
	case "name":
		return o.Name
	case "namespace":
		return o.Namespace
	case "propagate":
		return o.Propagate
	case "updateTime":
		return o.UpdateTime
	case "zHash":
		return o.ZHash
	case "zone":
		return o.Zone
	}

	return nil
}

// CustomDataTypeAttributesMap represents the map of attribute for CustomDataType.
var CustomDataTypeAttributesMap = map[string]elemental.AttributeSpecification{
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
	"CreateTime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "createtime",
		ConvertedName:  "CreateTime",
		Description:    `Creation date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "createTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
	"Description": {
		AllowedChoices: []string{},
		BSONFieldName:  "description",
		ConvertedName:  "Description",
		Description:    `Description of the custom data type.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"FriendlyName": {
		AllowedChoices: []string{},
		BSONFieldName:  "friendlyname",
		ConvertedName:  "FriendlyName",
		Description:    `Friendly name of the object.`,
		Exposed:        true,
		Name:           "friendlyName",
		Required:       true,
		Stored:         true,
		Type:           "string",
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
	"Matches": {
		AllowedChoices: []string{},
		BSONFieldName:  "matches",
		ConvertedName:  "Matches",
		Description: `A list of RE2 regular expressions used for data detection. Each expression can
include zero or one capturing group. If no capturing group is present, detection
positions will be determined based on the entire captured portion of the data.
If a single capturing group is included, the detection positions will correspond
to the part defined by that group. However, if more than one capturing group is
found, the system will return a validation error. Additionally, extra
validations are performed to ensure that the regular expressions are not overly
complex, preventing any negative impact on detection engine performance.`,
		Exposed: true,
		Name:    "matches",
		Stored:  true,
		SubType: "string",
		Type:    "list",
	},
	"Name": {
		AllowedChars:   `^[a-zA-Z0-9-_]+$`,
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		CreationOnly:   true,
		Description: `The internal reference name of the object. It is a sanitized version of Friendly
Name if empty.`,
		Exposed: true,
		Name:    "name",
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
	"Propagate": {
		AllowedChoices: []string{},
		BSONFieldName:  "propagate",
		ConvertedName:  "Propagate",
		DefaultValue:   true,
		Description:    `Propagates the object to all child namespaces. This is always true.`,
		Exposed:        true,
		Getter:         true,
		Name:           "propagate",
		Setter:         true,
		Stored:         true,
		Type:           "boolean",
	},
	"UpdateTime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "updatetime",
		ConvertedName:  "UpdateTime",
		Description:    `Last update date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "updateTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
}

// CustomDataTypeLowerCaseAttributesMap represents the map of attribute for CustomDataType.
var CustomDataTypeLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
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
	"createtime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "createtime",
		ConvertedName:  "CreateTime",
		Description:    `Creation date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "createTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
	"description": {
		AllowedChoices: []string{},
		BSONFieldName:  "description",
		ConvertedName:  "Description",
		Description:    `Description of the custom data type.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"friendlyname": {
		AllowedChoices: []string{},
		BSONFieldName:  "friendlyname",
		ConvertedName:  "FriendlyName",
		Description:    `Friendly name of the object.`,
		Exposed:        true,
		Name:           "friendlyName",
		Required:       true,
		Stored:         true,
		Type:           "string",
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
	"matches": {
		AllowedChoices: []string{},
		BSONFieldName:  "matches",
		ConvertedName:  "Matches",
		Description: `A list of RE2 regular expressions used for data detection. Each expression can
include zero or one capturing group. If no capturing group is present, detection
positions will be determined based on the entire captured portion of the data.
If a single capturing group is included, the detection positions will correspond
to the part defined by that group. However, if more than one capturing group is
found, the system will return a validation error. Additionally, extra
validations are performed to ensure that the regular expressions are not overly
complex, preventing any negative impact on detection engine performance.`,
		Exposed: true,
		Name:    "matches",
		Stored:  true,
		SubType: "string",
		Type:    "list",
	},
	"name": {
		AllowedChars:   `^[a-zA-Z0-9-_]+$`,
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		CreationOnly:   true,
		Description: `The internal reference name of the object. It is a sanitized version of Friendly
Name if empty.`,
		Exposed: true,
		Name:    "name",
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
	"propagate": {
		AllowedChoices: []string{},
		BSONFieldName:  "propagate",
		ConvertedName:  "Propagate",
		DefaultValue:   true,
		Description:    `Propagates the object to all child namespaces. This is always true.`,
		Exposed:        true,
		Getter:         true,
		Name:           "propagate",
		Setter:         true,
		Stored:         true,
		Type:           "boolean",
	},
	"updatetime": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "updatetime",
		ConvertedName:  "UpdateTime",
		Description:    `Last update date of the object.`,
		Exposed:        true,
		Getter:         true,
		Name:           "updateTime",
		Orderable:      true,
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "time",
	},
}

// SparseCustomDataTypesList represents a list of SparseCustomDataTypes
type SparseCustomDataTypesList []*SparseCustomDataType

// Identity returns the identity of the objects in the list.
func (o SparseCustomDataTypesList) Identity() elemental.Identity {

	return CustomDataTypeIdentity
}

// Copy returns a pointer to a copy the SparseCustomDataTypesList.
func (o SparseCustomDataTypesList) Copy() elemental.Identifiables {

	copy := append(SparseCustomDataTypesList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseCustomDataTypesList.
func (o SparseCustomDataTypesList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseCustomDataTypesList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseCustomDataType))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseCustomDataTypesList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseCustomDataTypesList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseCustomDataTypesList converted to CustomDataTypesList.
func (o SparseCustomDataTypesList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseCustomDataTypesList) Version() int {

	return 1
}

// SparseCustomDataType represents the sparse version of a customdatatype.
type SparseCustomDataType struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime *time.Time `json:"createTime,omitempty" msgpack:"createTime,omitempty" bson:"createtime,omitempty" mapstructure:"createTime,omitempty"`

	// Description of the custom data type.
	Description *string `json:"description,omitempty" msgpack:"description,omitempty" bson:"description,omitempty" mapstructure:"description,omitempty"`

	// Friendly name of the object.
	FriendlyName *string `json:"friendlyName,omitempty" msgpack:"friendlyName,omitempty" bson:"friendlyname,omitempty" mapstructure:"friendlyName,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash *string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel *string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// A list of RE2 regular expressions used for data detection. Each expression can
	// include zero or one capturing group. If no capturing group is present, detection
	// positions will be determined based on the entire captured portion of the data.
	// If a single capturing group is included, the detection positions will correspond
	// to the part defined by that group. However, if more than one capturing group is
	// found, the system will return a validation error. Additionally, extra
	// validations are performed to ensure that the regular expressions are not overly
	// complex, preventing any negative impact on detection engine performance.
	Matches *[]string `json:"matches,omitempty" msgpack:"matches,omitempty" bson:"matches,omitempty" mapstructure:"matches,omitempty"`

	// The internal reference name of the object. It is a sanitized version of Friendly
	// Name if empty.
	Name *string `json:"name,omitempty" msgpack:"name,omitempty" bson:"name,omitempty" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// Propagates the object to all child namespaces. This is always true.
	Propagate *bool `json:"propagate,omitempty" msgpack:"propagate,omitempty" bson:"propagate,omitempty" mapstructure:"propagate,omitempty"`

	// Last update date of the object.
	UpdateTime *time.Time `json:"updateTime,omitempty" msgpack:"updateTime,omitempty" bson:"updatetime,omitempty" mapstructure:"updateTime,omitempty"`

	// Hash of the object used to shard the data.
	ZHash *int `json:"-" msgpack:"-" bson:"zhash,omitempty" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone *int `json:"-" msgpack:"-" bson:"zone,omitempty" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseCustomDataType returns a new  SparseCustomDataType.
func NewSparseCustomDataType() *SparseCustomDataType {
	return &SparseCustomDataType{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseCustomDataType) Identity() elemental.Identity {

	return CustomDataTypeIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseCustomDataType) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseCustomDataType) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseCustomDataType) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseCustomDataType{}

	if o.ID != nil {
		s.ID = bson.ObjectIdHex(*o.ID)
	}
	if o.CreateTime != nil {
		s.CreateTime = o.CreateTime
	}
	if o.Description != nil {
		s.Description = o.Description
	}
	if o.FriendlyName != nil {
		s.FriendlyName = o.FriendlyName
	}
	if o.ImportHash != nil {
		s.ImportHash = o.ImportHash
	}
	if o.ImportLabel != nil {
		s.ImportLabel = o.ImportLabel
	}
	if o.Matches != nil {
		s.Matches = o.Matches
	}
	if o.Name != nil {
		s.Name = o.Name
	}
	if o.Namespace != nil {
		s.Namespace = o.Namespace
	}
	if o.Propagate != nil {
		s.Propagate = o.Propagate
	}
	if o.UpdateTime != nil {
		s.UpdateTime = o.UpdateTime
	}
	if o.ZHash != nil {
		s.ZHash = o.ZHash
	}
	if o.Zone != nil {
		s.Zone = o.Zone
	}

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseCustomDataType) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseCustomDataType{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	id := s.ID.Hex()
	o.ID = &id
	if s.CreateTime != nil {
		o.CreateTime = s.CreateTime
	}
	if s.Description != nil {
		o.Description = s.Description
	}
	if s.FriendlyName != nil {
		o.FriendlyName = s.FriendlyName
	}
	if s.ImportHash != nil {
		o.ImportHash = s.ImportHash
	}
	if s.ImportLabel != nil {
		o.ImportLabel = s.ImportLabel
	}
	if s.Matches != nil {
		o.Matches = s.Matches
	}
	if s.Name != nil {
		o.Name = s.Name
	}
	if s.Namespace != nil {
		o.Namespace = s.Namespace
	}
	if s.Propagate != nil {
		o.Propagate = s.Propagate
	}
	if s.UpdateTime != nil {
		o.UpdateTime = s.UpdateTime
	}
	if s.ZHash != nil {
		o.ZHash = s.ZHash
	}
	if s.Zone != nil {
		o.Zone = s.Zone
	}

	return nil
}

// Version returns the hardcoded version of the model.
func (o *SparseCustomDataType) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseCustomDataType) ToPlain() elemental.PlainIdentifiable {

	out := NewCustomDataType()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.CreateTime != nil {
		out.CreateTime = *o.CreateTime
	}
	if o.Description != nil {
		out.Description = *o.Description
	}
	if o.FriendlyName != nil {
		out.FriendlyName = *o.FriendlyName
	}
	if o.ImportHash != nil {
		out.ImportHash = *o.ImportHash
	}
	if o.ImportLabel != nil {
		out.ImportLabel = *o.ImportLabel
	}
	if o.Matches != nil {
		out.Matches = *o.Matches
	}
	if o.Name != nil {
		out.Name = *o.Name
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.Propagate != nil {
		out.Propagate = *o.Propagate
	}
	if o.UpdateTime != nil {
		out.UpdateTime = *o.UpdateTime
	}
	if o.ZHash != nil {
		out.ZHash = *o.ZHash
	}
	if o.Zone != nil {
		out.Zone = *o.Zone
	}

	return out
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *SparseCustomDataType) GetCreateTime() (out time.Time) {

	if o.CreateTime == nil {
		return
	}

	return *o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the address of the given value.
func (o *SparseCustomDataType) SetCreateTime(createTime time.Time) {

	o.CreateTime = &createTime
}

// GetImportHash returns the ImportHash of the receiver.
func (o *SparseCustomDataType) GetImportHash() (out string) {

	if o.ImportHash == nil {
		return
	}

	return *o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the address of the given value.
func (o *SparseCustomDataType) SetImportHash(importHash string) {

	o.ImportHash = &importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *SparseCustomDataType) GetImportLabel() (out string) {

	if o.ImportLabel == nil {
		return
	}

	return *o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the address of the given value.
func (o *SparseCustomDataType) SetImportLabel(importLabel string) {

	o.ImportLabel = &importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseCustomDataType) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseCustomDataType) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// GetPropagate returns the Propagate of the receiver.
func (o *SparseCustomDataType) GetPropagate() (out bool) {

	if o.Propagate == nil {
		return
	}

	return *o.Propagate
}

// SetPropagate sets the property Propagate of the receiver using the address of the given value.
func (o *SparseCustomDataType) SetPropagate(propagate bool) {

	o.Propagate = &propagate
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *SparseCustomDataType) GetUpdateTime() (out time.Time) {

	if o.UpdateTime == nil {
		return
	}

	return *o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the address of the given value.
func (o *SparseCustomDataType) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = &updateTime
}

// DeepCopy returns a deep copy if the SparseCustomDataType.
func (o *SparseCustomDataType) DeepCopy() *SparseCustomDataType {

	if o == nil {
		return nil
	}

	out := &SparseCustomDataType{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseCustomDataType.
func (o *SparseCustomDataType) DeepCopyInto(out *SparseCustomDataType) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseCustomDataType: %s", err))
	}

	*out = *target.(*SparseCustomDataType)
}

type mongoAttributesCustomDataType struct {
	ID           bson.ObjectId `bson:"_id,omitempty"`
	CreateTime   time.Time     `bson:"createtime"`
	Description  string        `bson:"description"`
	FriendlyName string        `bson:"friendlyname"`
	ImportHash   string        `bson:"importhash,omitempty"`
	ImportLabel  string        `bson:"importlabel,omitempty"`
	Matches      []string      `bson:"matches"`
	Name         string        `bson:"name"`
	Namespace    string        `bson:"namespace,omitempty"`
	Propagate    bool          `bson:"propagate"`
	UpdateTime   time.Time     `bson:"updatetime"`
	ZHash        int           `bson:"zhash"`
	Zone         int           `bson:"zone"`
}
type mongoAttributesSparseCustomDataType struct {
	ID           bson.ObjectId `bson:"_id,omitempty"`
	CreateTime   *time.Time    `bson:"createtime,omitempty"`
	Description  *string       `bson:"description,omitempty"`
	FriendlyName *string       `bson:"friendlyname,omitempty"`
	ImportHash   *string       `bson:"importhash,omitempty"`
	ImportLabel  *string       `bson:"importlabel,omitempty"`
	Matches      *[]string     `bson:"matches,omitempty"`
	Name         *string       `bson:"name,omitempty"`
	Namespace    *string       `bson:"namespace,omitempty"`
	Propagate    *bool         `bson:"propagate,omitempty"`
	UpdateTime   *time.Time    `bson:"updatetime,omitempty"`
	ZHash        *int          `bson:"zhash,omitempty"`
	Zone         *int          `bson:"zone,omitempty"`
}
