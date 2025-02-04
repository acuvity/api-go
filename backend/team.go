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

// TeamIdentity represents the Identity of the object.
var TeamIdentity = elemental.Identity{
	Name:     "team",
	Category: "teams",
	Package:  "lain",
	Private:  false,
}

// TeamsList represents a list of Teams
type TeamsList []*Team

// Identity returns the identity of the objects in the list.
func (o TeamsList) Identity() elemental.Identity {

	return TeamIdentity
}

// Copy returns a pointer to a copy the TeamsList.
func (o TeamsList) Copy() elemental.Identifiables {

	out := append(TeamsList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the TeamsList.
func (o TeamsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(TeamsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*Team))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o TeamsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o TeamsList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the TeamsList converted to SparseTeamsList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o TeamsList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseTeamsList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseTeam)
	}

	return out
}

// Version returns the version of the content.
func (o TeamsList) Version() int {

	return 1
}

// Team represents the model of a team
type Team struct {
	// ID is the identifier of the object.
	ID string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime time.Time `json:"createTime" msgpack:"createTime" bson:"createtime" mapstructure:"createTime,omitempty"`

	// Description of the team.
	Description string `json:"description" msgpack:"description" bson:"description" mapstructure:"description,omitempty"`

	// Set the team to be disabled.
	Disabled bool `json:"disabled" msgpack:"disabled" bson:"disabled" mapstructure:"disabled,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// The name of the team.
	Name string `json:"name" msgpack:"name" bson:"name" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// A tag expression that identifies user(s).
	Subject [][]string `json:"subject" msgpack:"subject" bson:"subject" mapstructure:"subject,omitempty"`

	// Last update date of the object.
	UpdateTime time.Time `json:"updateTime" msgpack:"updateTime" bson:"updatetime" mapstructure:"updateTime,omitempty"`

	// Weight of the team. It is used if multiple teams match for a user. In that case
	// the team with the higher weight will be used.
	Weight int `json:"weight" msgpack:"weight" bson:"weight" mapstructure:"weight,omitempty"`

	// Hash of the object used to shard the data.
	ZHash int `json:"-" msgpack:"-" bson:"zhash" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone int `json:"-" msgpack:"-" bson:"zone" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewTeam returns a new *Team
func NewTeam() *Team {

	return &Team{
		ModelVersion: 1,
		Subject:      [][]string{},
	}
}

// Identity returns the Identity of the object.
func (o *Team) Identity() elemental.Identity {

	return TeamIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *Team) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *Team) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Team) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesTeam{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.CreateTime = o.CreateTime
	s.Description = o.Description
	s.Disabled = o.Disabled
	s.ImportHash = o.ImportHash
	s.ImportLabel = o.ImportLabel
	s.Name = o.Name
	s.Namespace = o.Namespace
	s.Subject = o.Subject
	s.UpdateTime = o.UpdateTime
	s.Weight = o.Weight
	s.ZHash = o.ZHash
	s.Zone = o.Zone

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *Team) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesTeam{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.CreateTime = s.CreateTime
	o.Description = s.Description
	o.Disabled = s.Disabled
	o.ImportHash = s.ImportHash
	o.ImportLabel = s.ImportLabel
	o.Name = s.Name
	o.Namespace = s.Namespace
	o.Subject = s.Subject
	o.UpdateTime = s.UpdateTime
	o.Weight = s.Weight
	o.ZHash = s.ZHash
	o.Zone = s.Zone

	return nil
}

// Version returns the hardcoded version of the model.
func (o *Team) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *Team) BleveType() string {

	return "team"
}

// DefaultOrder returns the list of default ordering fields.
func (o *Team) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *Team) Doc() string {

	return `Teams can be created to create groups of people, identified by their jwt claims
that can be used when writing authorizations.`
}

func (o *Team) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *Team) GetCreateTime() time.Time {

	return o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the given value.
func (o *Team) SetCreateTime(createTime time.Time) {

	o.CreateTime = createTime
}

// GetImportHash returns the ImportHash of the receiver.
func (o *Team) GetImportHash() string {

	return o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the given value.
func (o *Team) SetImportHash(importHash string) {

	o.ImportHash = importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *Team) GetImportLabel() string {

	return o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the given value.
func (o *Team) SetImportLabel(importLabel string) {

	o.ImportLabel = importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *Team) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *Team) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *Team) GetUpdateTime() time.Time {

	return o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the given value.
func (o *Team) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *Team) GetZHash() int {

	return o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the given value.
func (o *Team) SetZHash(zHash int) {

	o.ZHash = zHash
}

// GetZone returns the Zone of the receiver.
func (o *Team) GetZone() int {

	return o.Zone
}

// SetZone sets the property Zone of the receiver using the given value.
func (o *Team) SetZone(zone int) {

	o.Zone = zone
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *Team) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseTeam{
			ID:          &o.ID,
			CreateTime:  &o.CreateTime,
			Description: &o.Description,
			Disabled:    &o.Disabled,
			ImportHash:  &o.ImportHash,
			ImportLabel: &o.ImportLabel,
			Name:        &o.Name,
			Namespace:   &o.Namespace,
			Subject:     &o.Subject,
			UpdateTime:  &o.UpdateTime,
			Weight:      &o.Weight,
			ZHash:       &o.ZHash,
			Zone:        &o.Zone,
		}
	}

	sp := &SparseTeam{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "createTime":
			sp.CreateTime = &(o.CreateTime)
		case "description":
			sp.Description = &(o.Description)
		case "disabled":
			sp.Disabled = &(o.Disabled)
		case "importHash":
			sp.ImportHash = &(o.ImportHash)
		case "importLabel":
			sp.ImportLabel = &(o.ImportLabel)
		case "name":
			sp.Name = &(o.Name)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "subject":
			sp.Subject = &(o.Subject)
		case "updateTime":
			sp.UpdateTime = &(o.UpdateTime)
		case "weight":
			sp.Weight = &(o.Weight)
		case "zHash":
			sp.ZHash = &(o.ZHash)
		case "zone":
			sp.Zone = &(o.Zone)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseTeam to the object.
func (o *Team) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseTeam)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.CreateTime != nil {
		o.CreateTime = *so.CreateTime
	}
	if so.Description != nil {
		o.Description = *so.Description
	}
	if so.Disabled != nil {
		o.Disabled = *so.Disabled
	}
	if so.ImportHash != nil {
		o.ImportHash = *so.ImportHash
	}
	if so.ImportLabel != nil {
		o.ImportLabel = *so.ImportLabel
	}
	if so.Name != nil {
		o.Name = *so.Name
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.Subject != nil {
		o.Subject = *so.Subject
	}
	if so.UpdateTime != nil {
		o.UpdateTime = *so.UpdateTime
	}
	if so.Weight != nil {
		o.Weight = *so.Weight
	}
	if so.ZHash != nil {
		o.ZHash = *so.ZHash
	}
	if so.Zone != nil {
		o.Zone = *so.Zone
	}
}

// DeepCopy returns a deep copy if the Team.
func (o *Team) DeepCopy() *Team {

	if o == nil {
		return nil
	}

	out := &Team{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *Team.
func (o *Team) DeepCopyInto(out *Team) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy Team: %s", err))
	}

	*out = *target.(*Team)
}

// Validate valides the current information stored into the structure.
func (o *Team) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateRequiredString("name", o.Name); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := elemental.ValidatePattern("name", o.Name, `^[a-zA-Z0-9-_/@. ]+$`, `must only contain alpha numerical characters, '-' or '_' or '@' or '.' or space.`, true); err != nil {
		errors = errors.Append(err)
	}

	if err := ValidateAuthorizationSubject("subject", o.Subject); err != nil {
		errors = errors.Append(err)
	}
	if err := ValidateTagsExpression("subject", o.Subject); err != nil {
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
func (*Team) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := TeamAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return TeamLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*Team) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return TeamAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *Team) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "createTime":
		return o.CreateTime
	case "description":
		return o.Description
	case "disabled":
		return o.Disabled
	case "importHash":
		return o.ImportHash
	case "importLabel":
		return o.ImportLabel
	case "name":
		return o.Name
	case "namespace":
		return o.Namespace
	case "subject":
		return o.Subject
	case "updateTime":
		return o.UpdateTime
	case "weight":
		return o.Weight
	case "zHash":
		return o.ZHash
	case "zone":
		return o.Zone
	}

	return nil
}

// TeamAttributesMap represents the map of attribute for Team.
var TeamAttributesMap = map[string]elemental.AttributeSpecification{
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
		Description:    `Description of the team.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"Disabled": {
		AllowedChoices: []string{},
		BSONFieldName:  "disabled",
		ConvertedName:  "Disabled",
		Description:    `Set the team to be disabled.`,
		Exposed:        true,
		Name:           "disabled",
		Stored:         true,
		Type:           "boolean",
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
	"Name": {
		AllowedChars:   `^[a-zA-Z0-9-_/@. ]+$`,
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		CreationOnly:   true,
		Description:    `The name of the team.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Stored:         true,
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
	"Subject": {
		AllowedChoices: []string{},
		BSONFieldName:  "subject",
		ConvertedName:  "Subject",
		Description:    `A tag expression that identifies user(s).`,
		Exposed:        true,
		Name:           "subject",
		Orderable:      true,
		Stored:         true,
		SubType:        "[][]string",
		Type:           "external",
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
	"Weight": {
		AllowedChoices: []string{},
		BSONFieldName:  "weight",
		ConvertedName:  "Weight",
		Description: `Weight of the team. It is used if multiple teams match for a user. In that case
the team with the higher weight will be used.`,
		Exposed: true,
		Name:    "weight",
		Stored:  true,
		Type:    "integer",
	},
	"ZHash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zhash",
		ConvertedName:  "ZHash",
		Description:    `Hash of the object used to shard the data.`,
		Getter:         true,
		Name:           "zHash",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "integer",
	},
	"Zone": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zone",
		ConvertedName:  "Zone",
		Description:    `Sharding zone.`,
		Getter:         true,
		Name:           "zone",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Transient:      true,
		Type:           "integer",
	},
}

// TeamLowerCaseAttributesMap represents the map of attribute for Team.
var TeamLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
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
		Description:    `Description of the team.`,
		Exposed:        true,
		Name:           "description",
		Stored:         true,
		Type:           "string",
	},
	"disabled": {
		AllowedChoices: []string{},
		BSONFieldName:  "disabled",
		ConvertedName:  "Disabled",
		Description:    `Set the team to be disabled.`,
		Exposed:        true,
		Name:           "disabled",
		Stored:         true,
		Type:           "boolean",
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
	"name": {
		AllowedChars:   `^[a-zA-Z0-9-_/@. ]+$`,
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		CreationOnly:   true,
		Description:    `The name of the team.`,
		Exposed:        true,
		Name:           "name",
		Required:       true,
		Stored:         true,
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
	"subject": {
		AllowedChoices: []string{},
		BSONFieldName:  "subject",
		ConvertedName:  "Subject",
		Description:    `A tag expression that identifies user(s).`,
		Exposed:        true,
		Name:           "subject",
		Orderable:      true,
		Stored:         true,
		SubType:        "[][]string",
		Type:           "external",
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
	"weight": {
		AllowedChoices: []string{},
		BSONFieldName:  "weight",
		ConvertedName:  "Weight",
		Description: `Weight of the team. It is used if multiple teams match for a user. In that case
the team with the higher weight will be used.`,
		Exposed: true,
		Name:    "weight",
		Stored:  true,
		Type:    "integer",
	},
	"zhash": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zhash",
		ConvertedName:  "ZHash",
		Description:    `Hash of the object used to shard the data.`,
		Getter:         true,
		Name:           "zHash",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Type:           "integer",
	},
	"zone": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "zone",
		ConvertedName:  "Zone",
		Description:    `Sharding zone.`,
		Getter:         true,
		Name:           "zone",
		ReadOnly:       true,
		Setter:         true,
		Stored:         true,
		Transient:      true,
		Type:           "integer",
	},
}

// SparseTeamsList represents a list of SparseTeams
type SparseTeamsList []*SparseTeam

// Identity returns the identity of the objects in the list.
func (o SparseTeamsList) Identity() elemental.Identity {

	return TeamIdentity
}

// Copy returns a pointer to a copy the SparseTeamsList.
func (o SparseTeamsList) Copy() elemental.Identifiables {

	copy := append(SparseTeamsList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseTeamsList.
func (o SparseTeamsList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseTeamsList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseTeam))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseTeamsList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseTeamsList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseTeamsList converted to TeamsList.
func (o SparseTeamsList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseTeamsList) Version() int {

	return 1
}

// SparseTeam represents the sparse version of a team.
type SparseTeam struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// Creation date of the object.
	CreateTime *time.Time `json:"createTime,omitempty" msgpack:"createTime,omitempty" bson:"createtime,omitempty" mapstructure:"createTime,omitempty"`

	// Description of the team.
	Description *string `json:"description,omitempty" msgpack:"description,omitempty" bson:"description,omitempty" mapstructure:"description,omitempty"`

	// Set the team to be disabled.
	Disabled *bool `json:"disabled,omitempty" msgpack:"disabled,omitempty" bson:"disabled,omitempty" mapstructure:"disabled,omitempty"`

	// The hash of the structure used to compare with new import version.
	ImportHash *string `json:"importHash,omitempty" msgpack:"importHash,omitempty" bson:"importhash,omitempty" mapstructure:"importHash,omitempty"`

	// The user-defined import label that allows the system to group resources from the
	// same import operation.
	ImportLabel *string `json:"importLabel,omitempty" msgpack:"importLabel,omitempty" bson:"importlabel,omitempty" mapstructure:"importLabel,omitempty"`

	// The name of the team.
	Name *string `json:"name,omitempty" msgpack:"name,omitempty" bson:"name,omitempty" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// A tag expression that identifies user(s).
	Subject *[][]string `json:"subject,omitempty" msgpack:"subject,omitempty" bson:"subject,omitempty" mapstructure:"subject,omitempty"`

	// Last update date of the object.
	UpdateTime *time.Time `json:"updateTime,omitempty" msgpack:"updateTime,omitempty" bson:"updatetime,omitempty" mapstructure:"updateTime,omitempty"`

	// Weight of the team. It is used if multiple teams match for a user. In that case
	// the team with the higher weight will be used.
	Weight *int `json:"weight,omitempty" msgpack:"weight,omitempty" bson:"weight,omitempty" mapstructure:"weight,omitempty"`

	// Hash of the object used to shard the data.
	ZHash *int `json:"-" msgpack:"-" bson:"zhash,omitempty" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone *int `json:"-" msgpack:"-" bson:"zone,omitempty" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseTeam returns a new  SparseTeam.
func NewSparseTeam() *SparseTeam {
	return &SparseTeam{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseTeam) Identity() elemental.Identity {

	return TeamIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseTeam) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseTeam) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseTeam) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseTeam{}

	if o.ID != nil {
		s.ID = bson.ObjectIdHex(*o.ID)
	}
	if o.CreateTime != nil {
		s.CreateTime = o.CreateTime
	}
	if o.Description != nil {
		s.Description = o.Description
	}
	if o.Disabled != nil {
		s.Disabled = o.Disabled
	}
	if o.ImportHash != nil {
		s.ImportHash = o.ImportHash
	}
	if o.ImportLabel != nil {
		s.ImportLabel = o.ImportLabel
	}
	if o.Name != nil {
		s.Name = o.Name
	}
	if o.Namespace != nil {
		s.Namespace = o.Namespace
	}
	if o.Subject != nil {
		s.Subject = o.Subject
	}
	if o.UpdateTime != nil {
		s.UpdateTime = o.UpdateTime
	}
	if o.Weight != nil {
		s.Weight = o.Weight
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
func (o *SparseTeam) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseTeam{}
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
	if s.Disabled != nil {
		o.Disabled = s.Disabled
	}
	if s.ImportHash != nil {
		o.ImportHash = s.ImportHash
	}
	if s.ImportLabel != nil {
		o.ImportLabel = s.ImportLabel
	}
	if s.Name != nil {
		o.Name = s.Name
	}
	if s.Namespace != nil {
		o.Namespace = s.Namespace
	}
	if s.Subject != nil {
		o.Subject = s.Subject
	}
	if s.UpdateTime != nil {
		o.UpdateTime = s.UpdateTime
	}
	if s.Weight != nil {
		o.Weight = s.Weight
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
func (o *SparseTeam) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseTeam) ToPlain() elemental.PlainIdentifiable {

	out := NewTeam()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.CreateTime != nil {
		out.CreateTime = *o.CreateTime
	}
	if o.Description != nil {
		out.Description = *o.Description
	}
	if o.Disabled != nil {
		out.Disabled = *o.Disabled
	}
	if o.ImportHash != nil {
		out.ImportHash = *o.ImportHash
	}
	if o.ImportLabel != nil {
		out.ImportLabel = *o.ImportLabel
	}
	if o.Name != nil {
		out.Name = *o.Name
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.Subject != nil {
		out.Subject = *o.Subject
	}
	if o.UpdateTime != nil {
		out.UpdateTime = *o.UpdateTime
	}
	if o.Weight != nil {
		out.Weight = *o.Weight
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
func (o *SparseTeam) GetCreateTime() (out time.Time) {

	if o.CreateTime == nil {
		return
	}

	return *o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the address of the given value.
func (o *SparseTeam) SetCreateTime(createTime time.Time) {

	o.CreateTime = &createTime
}

// GetImportHash returns the ImportHash of the receiver.
func (o *SparseTeam) GetImportHash() (out string) {

	if o.ImportHash == nil {
		return
	}

	return *o.ImportHash
}

// SetImportHash sets the property ImportHash of the receiver using the address of the given value.
func (o *SparseTeam) SetImportHash(importHash string) {

	o.ImportHash = &importHash
}

// GetImportLabel returns the ImportLabel of the receiver.
func (o *SparseTeam) GetImportLabel() (out string) {

	if o.ImportLabel == nil {
		return
	}

	return *o.ImportLabel
}

// SetImportLabel sets the property ImportLabel of the receiver using the address of the given value.
func (o *SparseTeam) SetImportLabel(importLabel string) {

	o.ImportLabel = &importLabel
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseTeam) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseTeam) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *SparseTeam) GetUpdateTime() (out time.Time) {

	if o.UpdateTime == nil {
		return
	}

	return *o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the address of the given value.
func (o *SparseTeam) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = &updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *SparseTeam) GetZHash() (out int) {

	if o.ZHash == nil {
		return
	}

	return *o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the address of the given value.
func (o *SparseTeam) SetZHash(zHash int) {

	o.ZHash = &zHash
}

// GetZone returns the Zone of the receiver.
func (o *SparseTeam) GetZone() (out int) {

	if o.Zone == nil {
		return
	}

	return *o.Zone
}

// SetZone sets the property Zone of the receiver using the address of the given value.
func (o *SparseTeam) SetZone(zone int) {

	o.Zone = &zone
}

// DeepCopy returns a deep copy if the SparseTeam.
func (o *SparseTeam) DeepCopy() *SparseTeam {

	if o == nil {
		return nil
	}

	out := &SparseTeam{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseTeam.
func (o *SparseTeam) DeepCopyInto(out *SparseTeam) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseTeam: %s", err))
	}

	*out = *target.(*SparseTeam)
}

type mongoAttributesTeam struct {
	ID          bson.ObjectId `bson:"_id,omitempty"`
	CreateTime  time.Time     `bson:"createtime"`
	Description string        `bson:"description"`
	Disabled    bool          `bson:"disabled"`
	ImportHash  string        `bson:"importhash,omitempty"`
	ImportLabel string        `bson:"importlabel,omitempty"`
	Name        string        `bson:"name"`
	Namespace   string        `bson:"namespace,omitempty"`
	Subject     [][]string    `bson:"subject"`
	UpdateTime  time.Time     `bson:"updatetime"`
	Weight      int           `bson:"weight"`
	ZHash       int           `bson:"zhash"`
	Zone        int           `bson:"zone"`
}
type mongoAttributesSparseTeam struct {
	ID          bson.ObjectId `bson:"_id,omitempty"`
	CreateTime  *time.Time    `bson:"createtime,omitempty"`
	Description *string       `bson:"description,omitempty"`
	Disabled    *bool         `bson:"disabled,omitempty"`
	ImportHash  *string       `bson:"importhash,omitempty"`
	ImportLabel *string       `bson:"importlabel,omitempty"`
	Name        *string       `bson:"name,omitempty"`
	Namespace   *string       `bson:"namespace,omitempty"`
	Subject     *[][]string   `bson:"subject,omitempty"`
	UpdateTime  *time.Time    `bson:"updatetime,omitempty"`
	Weight      *int          `bson:"weight,omitempty"`
	ZHash       *int          `bson:"zhash,omitempty"`
	Zone        *int          `bson:"zone,omitempty"`
}
