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

// UserTokenClientTypeValue represents the possible values for attribute "clientType".
type UserTokenClientTypeValue string

const (
	// UserTokenClientTypeAcushield represents the value Acushield.
	UserTokenClientTypeAcushield UserTokenClientTypeValue = "Acushield"

	// UserTokenClientTypeNone represents the value None.
	UserTokenClientTypeNone UserTokenClientTypeValue = "None"

	// UserTokenClientTypeWebExtension represents the value WebExtension.
	UserTokenClientTypeWebExtension UserTokenClientTypeValue = "WebExtension"
)

// UserTokenIdentity represents the Identity of the object.
var UserTokenIdentity = elemental.Identity{
	Name:     "usertoken",
	Category: "usertokens",
	Package:  "lain",
	Private:  false,
}

// UserTokensList represents a list of UserTokens
type UserTokensList []*UserToken

// Identity returns the identity of the objects in the list.
func (o UserTokensList) Identity() elemental.Identity {

	return UserTokenIdentity
}

// Copy returns a pointer to a copy the UserTokensList.
func (o UserTokensList) Copy() elemental.Identifiables {

	out := append(UserTokensList{}, o...)
	return &out
}

// Append appends the objects to the a new copy of the UserTokensList.
func (o UserTokensList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(UserTokensList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*UserToken))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o UserTokensList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o UserTokensList) DefaultOrder() []string {

	return []string{}
}

// ToSparse returns the UserTokensList converted to SparseUserTokensList.
// Objects in the list will only contain the given fields. No field means entire field set.
func (o UserTokensList) ToSparse(fields ...string) elemental.Identifiables {

	out := make(SparseUserTokensList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToSparse(fields...).(*SparseUserToken)
	}

	return out
}

// Version returns the version of the content.
func (o UserTokensList) Version() int {

	return 1
}

// UserToken represents the model of a usertoken
type UserToken struct {
	// ID is the identifier of the object.
	ID string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The list of claims delivered in the token.
	Claims []string `json:"claims,omitempty" msgpack:"claims,omitempty" bson:"claims,omitempty" mapstructure:"claims,omitempty"`

	// the client type of the user token.
	ClientType UserTokenClientTypeValue `json:"clientType" msgpack:"clientType" bson:"clienttype" mapstructure:"clientType,omitempty"`

	// Creation date of the object.
	CreateTime time.Time `json:"createTime" msgpack:"createTime" bson:"createtime" mapstructure:"createTime,omitempty"`

	// The email of the user who requested the token.
	Email string `json:"email" msgpack:"email" bson:"email" mapstructure:"email,omitempty"`

	// Tells when the token will expire.
	ExpirationDate time.Time `json:"expirationDate" msgpack:"expirationDate" bson:"expirationdate" mapstructure:"expirationDate,omitempty"`

	// Name of the token is specified while creating the token.
	Name string `json:"name" msgpack:"name" bson:"name" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// The source IP of the request that initiated the creation of the token.
	SourceIP string `json:"sourceIP" msgpack:"sourceIP" bson:"sourceip" mapstructure:"sourceIP,omitempty"`

	// The generated token. It won't be stored.
	Token string `json:"token,omitempty" msgpack:"token,omitempty" bson:"-" mapstructure:"token,omitempty"`

	// The ID of the associated token.
	TokenID string `json:"tokenID" msgpack:"tokenID" bson:"tokenid" mapstructure:"tokenID,omitempty"`

	// If true, the token will not be stored and will only be revocable if you keep
	// track of the token ID yourself. Also, the validity will be capped and the token
	// won't be long lived.
	Transient bool `json:"transient,omitempty" msgpack:"transient,omitempty" bson:"transient,omitempty" mapstructure:"transient,omitempty"`

	// Last update date of the object.
	UpdateTime time.Time `json:"updateTime" msgpack:"updateTime" bson:"updatetime" mapstructure:"updateTime,omitempty"`

	// Configures the validity of the token.
	Validity string `json:"validity" msgpack:"validity" bson:"-" mapstructure:"validity,omitempty"`

	// Hash of the object used to shard the data.
	ZHash int `json:"-" msgpack:"-" bson:"zhash" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone int `json:"-" msgpack:"-" bson:"zone" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewUserToken returns a new *UserToken
func NewUserToken() *UserToken {

	return &UserToken{
		ModelVersion: 1,
		Claims:       []string{},
		ClientType:   UserTokenClientTypeNone,
		Validity:     "8760h",
	}
}

// Identity returns the Identity of the object.
func (o *UserToken) Identity() elemental.Identity {

	return UserTokenIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *UserToken) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *UserToken) SetIdentifier(id string) {

	o.ID = id
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *UserToken) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesUserToken{}

	if o.ID != "" {
		s.ID = bson.ObjectIdHex(o.ID)
	}
	s.Claims = o.Claims
	s.ClientType = o.ClientType
	s.CreateTime = o.CreateTime
	s.Email = o.Email
	s.ExpirationDate = o.ExpirationDate
	s.Name = o.Name
	s.Namespace = o.Namespace
	s.SourceIP = o.SourceIP
	s.TokenID = o.TokenID
	s.Transient = o.Transient
	s.UpdateTime = o.UpdateTime
	s.ZHash = o.ZHash
	s.Zone = o.Zone

	return s, nil
}

// SetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *UserToken) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesUserToken{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	o.ID = s.ID.Hex()
	o.Claims = s.Claims
	o.ClientType = s.ClientType
	o.CreateTime = s.CreateTime
	o.Email = s.Email
	o.ExpirationDate = s.ExpirationDate
	o.Name = s.Name
	o.Namespace = s.Namespace
	o.SourceIP = s.SourceIP
	o.TokenID = s.TokenID
	o.Transient = s.Transient
	o.UpdateTime = s.UpdateTime
	o.ZHash = s.ZHash
	o.Zone = s.Zone

	return nil
}

// Version returns the hardcoded version of the model.
func (o *UserToken) Version() int {

	return 1
}

// BleveType implements the bleve.Classifier Interface.
func (o *UserToken) BleveType() string {

	return "usertoken"
}

// DefaultOrder returns the list of default ordering fields.
func (o *UserToken) DefaultOrder() []string {

	return []string{}
}

// Doc returns the documentation for the object
func (o *UserToken) Doc() string {

	return `User Token are revocable long lived tokens for users.`
}

func (o *UserToken) String() string {

	return fmt.Sprintf("<%s:%s>", o.Identity().Name, o.Identifier())
}

// GetCreateTime returns the CreateTime of the receiver.
func (o *UserToken) GetCreateTime() time.Time {

	return o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the given value.
func (o *UserToken) SetCreateTime(createTime time.Time) {

	o.CreateTime = createTime
}

// GetNamespace returns the Namespace of the receiver.
func (o *UserToken) GetNamespace() string {

	return o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the given value.
func (o *UserToken) SetNamespace(namespace string) {

	o.Namespace = namespace
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *UserToken) GetUpdateTime() time.Time {

	return o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the given value.
func (o *UserToken) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *UserToken) GetZHash() int {

	return o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the given value.
func (o *UserToken) SetZHash(zHash int) {

	o.ZHash = zHash
}

// GetZone returns the Zone of the receiver.
func (o *UserToken) GetZone() int {

	return o.Zone
}

// SetZone sets the property Zone of the receiver using the given value.
func (o *UserToken) SetZone(zone int) {

	o.Zone = zone
}

// ToSparse returns the sparse version of the model.
// The returned object will only contain the given fields. No field means entire field set.
func (o *UserToken) ToSparse(fields ...string) elemental.SparseIdentifiable {

	if len(fields) == 0 {
		// nolint: goimports
		return &SparseUserToken{
			ID:             &o.ID,
			Claims:         &o.Claims,
			ClientType:     &o.ClientType,
			CreateTime:     &o.CreateTime,
			Email:          &o.Email,
			ExpirationDate: &o.ExpirationDate,
			Name:           &o.Name,
			Namespace:      &o.Namespace,
			SourceIP:       &o.SourceIP,
			Token:          &o.Token,
			TokenID:        &o.TokenID,
			Transient:      &o.Transient,
			UpdateTime:     &o.UpdateTime,
			Validity:       &o.Validity,
			ZHash:          &o.ZHash,
			Zone:           &o.Zone,
		}
	}

	sp := &SparseUserToken{}
	for _, f := range fields {
		switch f {
		case "ID":
			sp.ID = &(o.ID)
		case "claims":
			sp.Claims = &(o.Claims)
		case "clientType":
			sp.ClientType = &(o.ClientType)
		case "createTime":
			sp.CreateTime = &(o.CreateTime)
		case "email":
			sp.Email = &(o.Email)
		case "expirationDate":
			sp.ExpirationDate = &(o.ExpirationDate)
		case "name":
			sp.Name = &(o.Name)
		case "namespace":
			sp.Namespace = &(o.Namespace)
		case "sourceIP":
			sp.SourceIP = &(o.SourceIP)
		case "token":
			sp.Token = &(o.Token)
		case "tokenID":
			sp.TokenID = &(o.TokenID)
		case "transient":
			sp.Transient = &(o.Transient)
		case "updateTime":
			sp.UpdateTime = &(o.UpdateTime)
		case "validity":
			sp.Validity = &(o.Validity)
		case "zHash":
			sp.ZHash = &(o.ZHash)
		case "zone":
			sp.Zone = &(o.Zone)
		}
	}

	return sp
}

// Patch apply the non nil value of a *SparseUserToken to the object.
func (o *UserToken) Patch(sparse elemental.SparseIdentifiable) {
	if !sparse.Identity().IsEqual(o.Identity()) {
		panic("cannot patch from a parse with different identity")
	}

	so := sparse.(*SparseUserToken)
	if so.ID != nil {
		o.ID = *so.ID
	}
	if so.Claims != nil {
		o.Claims = *so.Claims
	}
	if so.ClientType != nil {
		o.ClientType = *so.ClientType
	}
	if so.CreateTime != nil {
		o.CreateTime = *so.CreateTime
	}
	if so.Email != nil {
		o.Email = *so.Email
	}
	if so.ExpirationDate != nil {
		o.ExpirationDate = *so.ExpirationDate
	}
	if so.Name != nil {
		o.Name = *so.Name
	}
	if so.Namespace != nil {
		o.Namespace = *so.Namespace
	}
	if so.SourceIP != nil {
		o.SourceIP = *so.SourceIP
	}
	if so.Token != nil {
		o.Token = *so.Token
	}
	if so.TokenID != nil {
		o.TokenID = *so.TokenID
	}
	if so.Transient != nil {
		o.Transient = *so.Transient
	}
	if so.UpdateTime != nil {
		o.UpdateTime = *so.UpdateTime
	}
	if so.Validity != nil {
		o.Validity = *so.Validity
	}
	if so.ZHash != nil {
		o.ZHash = *so.ZHash
	}
	if so.Zone != nil {
		o.Zone = *so.Zone
	}
}

// DeepCopy returns a deep copy if the UserToken.
func (o *UserToken) DeepCopy() *UserToken {

	if o == nil {
		return nil
	}

	out := &UserToken{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *UserToken.
func (o *UserToken) DeepCopyInto(out *UserToken) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy UserToken: %s", err))
	}

	*out = *target.(*UserToken)
}

// Validate valides the current information stored into the structure.
func (o *UserToken) Validate() error {

	errors := elemental.Errors{}
	requiredErrors := elemental.Errors{}

	if err := elemental.ValidateStringInList("clientType", string(o.ClientType), []string{"None", "WebExtension", "Acushield"}, false); err != nil {
		errors = errors.Append(err)
	}

	if err := elemental.ValidateRequiredString("name", o.Name); err != nil {
		requiredErrors = requiredErrors.Append(err)
	}

	if err := ValidateFriendlyName("name", o.Name); err != nil {
		errors = errors.Append(err)
	}

	if err := ValidateClientTokenValidity("validity", o.Validity); err != nil {
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
func (*UserToken) SpecificationForAttribute(name string) elemental.AttributeSpecification {

	if v, ok := UserTokenAttributesMap[name]; ok {
		return v
	}

	// We could not find it, so let's check on the lower case indexed spec map
	return UserTokenLowerCaseAttributesMap[name]
}

// AttributeSpecifications returns the full attribute specifications map.
func (*UserToken) AttributeSpecifications() map[string]elemental.AttributeSpecification {

	return UserTokenAttributesMap
}

// ValueForAttribute returns the value for the given attribute.
// This is a very advanced function that you should not need but in some
// very specific use cases.
func (o *UserToken) ValueForAttribute(name string) any {

	switch name {
	case "ID":
		return o.ID
	case "claims":
		return o.Claims
	case "clientType":
		return o.ClientType
	case "createTime":
		return o.CreateTime
	case "email":
		return o.Email
	case "expirationDate":
		return o.ExpirationDate
	case "name":
		return o.Name
	case "namespace":
		return o.Namespace
	case "sourceIP":
		return o.SourceIP
	case "token":
		return o.Token
	case "tokenID":
		return o.TokenID
	case "transient":
		return o.Transient
	case "updateTime":
		return o.UpdateTime
	case "validity":
		return o.Validity
	case "zHash":
		return o.ZHash
	case "zone":
		return o.Zone
	}

	return nil
}

// UserTokenAttributesMap represents the map of attribute for UserToken.
var UserTokenAttributesMap = map[string]elemental.AttributeSpecification{
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
	"Claims": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "claims",
		ConvertedName:  "Claims",
		Description:    `The list of claims delivered in the token.`,
		Exposed:        true,
		Name:           "claims",
		ReadOnly:       true,
		Stored:         true,
		SubType:        "string",
		Type:           "list",
	},
	"ClientType": {
		AllowedChoices: []string{"None", "WebExtension", "Acushield"},
		BSONFieldName:  "clienttype",
		ConvertedName:  "ClientType",
		DefaultValue:   UserTokenClientTypeNone,
		Description:    `the client type of the user token.`,
		Exposed:        true,
		Name:           "clientType",
		Stored:         true,
		Type:           "enum",
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
	"Email": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "email",
		ConvertedName:  "Email",
		Description:    `The email of the user who requested the token.`,
		Exposed:        true,
		Name:           "email",
		ReadOnly:       true,
		Stored:         true,
		Type:           "string",
	},
	"ExpirationDate": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "expirationdate",
		ConvertedName:  "ExpirationDate",
		Description:    `Tells when the token will expire.`,
		Exposed:        true,
		Name:           "expirationDate",
		ReadOnly:       true,
		Stored:         true,
		Type:           "time",
	},
	"Name": {
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		CreationOnly:   true,
		Description:    `Name of the token is specified while creating the token.`,
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
	"SourceIP": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "sourceip",
		ConvertedName:  "SourceIP",
		Description:    `The source IP of the request that initiated the creation of the token.`,
		Exposed:        true,
		Name:           "sourceIP",
		ReadOnly:       true,
		Stored:         true,
		Type:           "string",
	},
	"Token": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		ConvertedName:  "Token",
		Description:    `The generated token. It won't be stored.`,
		Exposed:        true,
		Name:           "token",
		Type:           "string",
	},
	"TokenID": {
		AllowedChoices: []string{},
		BSONFieldName:  "tokenid",
		ConvertedName:  "TokenID",
		Description:    `The ID of the associated token.`,
		Exposed:        true,
		Name:           "tokenID",
		Stored:         true,
		SubType:        "string",
		Type:           "string",
	},
	"Transient": {
		AllowedChoices: []string{},
		BSONFieldName:  "transient",
		ConvertedName:  "Transient",
		Description: `If true, the token will not be stored and will only be revocable if you keep
track of the token ID yourself. Also, the validity will be capped and the token
won't be long lived.`,
		Exposed: true,
		Name:    "transient",
		Stored:  true,
		Type:    "boolean",
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
	"Validity": {
		AllowedChoices: []string{},
		ConvertedName:  "Validity",
		DefaultValue:   "8760h",
		Description:    `Configures the validity of the token.`,
		Exposed:        true,
		Name:           "validity",
		Type:           "string",
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

// UserTokenLowerCaseAttributesMap represents the map of attribute for UserToken.
var UserTokenLowerCaseAttributesMap = map[string]elemental.AttributeSpecification{
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
	"claims": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "claims",
		ConvertedName:  "Claims",
		Description:    `The list of claims delivered in the token.`,
		Exposed:        true,
		Name:           "claims",
		ReadOnly:       true,
		Stored:         true,
		SubType:        "string",
		Type:           "list",
	},
	"clienttype": {
		AllowedChoices: []string{"None", "WebExtension", "Acushield"},
		BSONFieldName:  "clienttype",
		ConvertedName:  "ClientType",
		DefaultValue:   UserTokenClientTypeNone,
		Description:    `the client type of the user token.`,
		Exposed:        true,
		Name:           "clientType",
		Stored:         true,
		Type:           "enum",
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
	"email": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "email",
		ConvertedName:  "Email",
		Description:    `The email of the user who requested the token.`,
		Exposed:        true,
		Name:           "email",
		ReadOnly:       true,
		Stored:         true,
		Type:           "string",
	},
	"expirationdate": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "expirationdate",
		ConvertedName:  "ExpirationDate",
		Description:    `Tells when the token will expire.`,
		Exposed:        true,
		Name:           "expirationDate",
		ReadOnly:       true,
		Stored:         true,
		Type:           "time",
	},
	"name": {
		AllowedChoices: []string{},
		BSONFieldName:  "name",
		ConvertedName:  "Name",
		CreationOnly:   true,
		Description:    `Name of the token is specified while creating the token.`,
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
	"sourceip": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		BSONFieldName:  "sourceip",
		ConvertedName:  "SourceIP",
		Description:    `The source IP of the request that initiated the creation of the token.`,
		Exposed:        true,
		Name:           "sourceIP",
		ReadOnly:       true,
		Stored:         true,
		Type:           "string",
	},
	"token": {
		AllowedChoices: []string{},
		Autogenerated:  true,
		ConvertedName:  "Token",
		Description:    `The generated token. It won't be stored.`,
		Exposed:        true,
		Name:           "token",
		Type:           "string",
	},
	"tokenid": {
		AllowedChoices: []string{},
		BSONFieldName:  "tokenid",
		ConvertedName:  "TokenID",
		Description:    `The ID of the associated token.`,
		Exposed:        true,
		Name:           "tokenID",
		Stored:         true,
		SubType:        "string",
		Type:           "string",
	},
	"transient": {
		AllowedChoices: []string{},
		BSONFieldName:  "transient",
		ConvertedName:  "Transient",
		Description: `If true, the token will not be stored and will only be revocable if you keep
track of the token ID yourself. Also, the validity will be capped and the token
won't be long lived.`,
		Exposed: true,
		Name:    "transient",
		Stored:  true,
		Type:    "boolean",
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
	"validity": {
		AllowedChoices: []string{},
		ConvertedName:  "Validity",
		DefaultValue:   "8760h",
		Description:    `Configures the validity of the token.`,
		Exposed:        true,
		Name:           "validity",
		Type:           "string",
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

// SparseUserTokensList represents a list of SparseUserTokens
type SparseUserTokensList []*SparseUserToken

// Identity returns the identity of the objects in the list.
func (o SparseUserTokensList) Identity() elemental.Identity {

	return UserTokenIdentity
}

// Copy returns a pointer to a copy the SparseUserTokensList.
func (o SparseUserTokensList) Copy() elemental.Identifiables {

	copy := append(SparseUserTokensList{}, o...)
	return &copy
}

// Append appends the objects to the a new copy of the SparseUserTokensList.
func (o SparseUserTokensList) Append(objects ...elemental.Identifiable) elemental.Identifiables {

	out := append(SparseUserTokensList{}, o...)
	for _, obj := range objects {
		out = append(out, obj.(*SparseUserToken))
	}

	return out
}

// List converts the object to an elemental.IdentifiablesList.
func (o SparseUserTokensList) List() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i]
	}

	return out
}

// DefaultOrder returns the default ordering fields of the content.
func (o SparseUserTokensList) DefaultOrder() []string {

	return []string{}
}

// ToPlain returns the SparseUserTokensList converted to UserTokensList.
func (o SparseUserTokensList) ToPlain() elemental.IdentifiablesList {

	out := make(elemental.IdentifiablesList, len(o))
	for i := 0; i < len(o); i++ {
		out[i] = o[i].ToPlain()
	}

	return out
}

// Version returns the version of the content.
func (o SparseUserTokensList) Version() int {

	return 1
}

// SparseUserToken represents the sparse version of a usertoken.
type SparseUserToken struct {
	// ID is the identifier of the object.
	ID *string `json:"ID,omitempty" msgpack:"ID,omitempty" bson:"-" mapstructure:"ID,omitempty"`

	// The list of claims delivered in the token.
	Claims *[]string `json:"claims,omitempty" msgpack:"claims,omitempty" bson:"claims,omitempty" mapstructure:"claims,omitempty"`

	// the client type of the user token.
	ClientType *UserTokenClientTypeValue `json:"clientType,omitempty" msgpack:"clientType,omitempty" bson:"clienttype,omitempty" mapstructure:"clientType,omitempty"`

	// Creation date of the object.
	CreateTime *time.Time `json:"createTime,omitempty" msgpack:"createTime,omitempty" bson:"createtime,omitempty" mapstructure:"createTime,omitempty"`

	// The email of the user who requested the token.
	Email *string `json:"email,omitempty" msgpack:"email,omitempty" bson:"email,omitempty" mapstructure:"email,omitempty"`

	// Tells when the token will expire.
	ExpirationDate *time.Time `json:"expirationDate,omitempty" msgpack:"expirationDate,omitempty" bson:"expirationdate,omitempty" mapstructure:"expirationDate,omitempty"`

	// Name of the token is specified while creating the token.
	Name *string `json:"name,omitempty" msgpack:"name,omitempty" bson:"name,omitempty" mapstructure:"name,omitempty"`

	// The namespace of the object.
	Namespace *string `json:"namespace,omitempty" msgpack:"namespace,omitempty" bson:"namespace,omitempty" mapstructure:"namespace,omitempty"`

	// The source IP of the request that initiated the creation of the token.
	SourceIP *string `json:"sourceIP,omitempty" msgpack:"sourceIP,omitempty" bson:"sourceip,omitempty" mapstructure:"sourceIP,omitempty"`

	// The generated token. It won't be stored.
	Token *string `json:"token,omitempty" msgpack:"token,omitempty" bson:"-" mapstructure:"token,omitempty"`

	// The ID of the associated token.
	TokenID *string `json:"tokenID,omitempty" msgpack:"tokenID,omitempty" bson:"tokenid,omitempty" mapstructure:"tokenID,omitempty"`

	// If true, the token will not be stored and will only be revocable if you keep
	// track of the token ID yourself. Also, the validity will be capped and the token
	// won't be long lived.
	Transient *bool `json:"transient,omitempty" msgpack:"transient,omitempty" bson:"transient,omitempty" mapstructure:"transient,omitempty"`

	// Last update date of the object.
	UpdateTime *time.Time `json:"updateTime,omitempty" msgpack:"updateTime,omitempty" bson:"updatetime,omitempty" mapstructure:"updateTime,omitempty"`

	// Configures the validity of the token.
	Validity *string `json:"validity,omitempty" msgpack:"validity,omitempty" bson:"-" mapstructure:"validity,omitempty"`

	// Hash of the object used to shard the data.
	ZHash *int `json:"-" msgpack:"-" bson:"zhash,omitempty" mapstructure:"-,omitempty"`

	// Sharding zone.
	Zone *int `json:"-" msgpack:"-" bson:"zone,omitempty" mapstructure:"-,omitempty"`

	ModelVersion int `json:"-" msgpack:"-" bson:"_modelversion"`
}

// NewSparseUserToken returns a new  SparseUserToken.
func NewSparseUserToken() *SparseUserToken {
	return &SparseUserToken{}
}

// Identity returns the Identity of the sparse object.
func (o *SparseUserToken) Identity() elemental.Identity {

	return UserTokenIdentity
}

// Identifier returns the value of the sparse object's unique identifier.
func (o *SparseUserToken) Identifier() string {

	if o.ID == nil {
		return ""
	}
	return *o.ID
}

// SetIdentifier sets the value of the sparse object's unique identifier.
func (o *SparseUserToken) SetIdentifier(id string) {

	if id != "" {
		o.ID = &id
	} else {
		o.ID = nil
	}
}

// GetBSON implements the bson marshaling interface.
// This is used to transparently convert ID to MongoDBID as ObectID.
func (o *SparseUserToken) GetBSON() (any, error) {

	if o == nil {
		return nil, nil
	}

	s := &mongoAttributesSparseUserToken{}

	if o.ID != nil {
		s.ID = bson.ObjectIdHex(*o.ID)
	}
	if o.Claims != nil {
		s.Claims = o.Claims
	}
	if o.ClientType != nil {
		s.ClientType = o.ClientType
	}
	if o.CreateTime != nil {
		s.CreateTime = o.CreateTime
	}
	if o.Email != nil {
		s.Email = o.Email
	}
	if o.ExpirationDate != nil {
		s.ExpirationDate = o.ExpirationDate
	}
	if o.Name != nil {
		s.Name = o.Name
	}
	if o.Namespace != nil {
		s.Namespace = o.Namespace
	}
	if o.SourceIP != nil {
		s.SourceIP = o.SourceIP
	}
	if o.TokenID != nil {
		s.TokenID = o.TokenID
	}
	if o.Transient != nil {
		s.Transient = o.Transient
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
func (o *SparseUserToken) SetBSON(raw bson.Raw) error {

	if o == nil {
		return nil
	}

	s := &mongoAttributesSparseUserToken{}
	if err := raw.Unmarshal(s); err != nil {
		return err
	}

	id := s.ID.Hex()
	o.ID = &id
	if s.Claims != nil {
		o.Claims = s.Claims
	}
	if s.ClientType != nil {
		o.ClientType = s.ClientType
	}
	if s.CreateTime != nil {
		o.CreateTime = s.CreateTime
	}
	if s.Email != nil {
		o.Email = s.Email
	}
	if s.ExpirationDate != nil {
		o.ExpirationDate = s.ExpirationDate
	}
	if s.Name != nil {
		o.Name = s.Name
	}
	if s.Namespace != nil {
		o.Namespace = s.Namespace
	}
	if s.SourceIP != nil {
		o.SourceIP = s.SourceIP
	}
	if s.TokenID != nil {
		o.TokenID = s.TokenID
	}
	if s.Transient != nil {
		o.Transient = s.Transient
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
func (o *SparseUserToken) Version() int {

	return 1
}

// ToPlain returns the plain version of the sparse model.
func (o *SparseUserToken) ToPlain() elemental.PlainIdentifiable {

	out := NewUserToken()
	if o.ID != nil {
		out.ID = *o.ID
	}
	if o.Claims != nil {
		out.Claims = *o.Claims
	}
	if o.ClientType != nil {
		out.ClientType = *o.ClientType
	}
	if o.CreateTime != nil {
		out.CreateTime = *o.CreateTime
	}
	if o.Email != nil {
		out.Email = *o.Email
	}
	if o.ExpirationDate != nil {
		out.ExpirationDate = *o.ExpirationDate
	}
	if o.Name != nil {
		out.Name = *o.Name
	}
	if o.Namespace != nil {
		out.Namespace = *o.Namespace
	}
	if o.SourceIP != nil {
		out.SourceIP = *o.SourceIP
	}
	if o.Token != nil {
		out.Token = *o.Token
	}
	if o.TokenID != nil {
		out.TokenID = *o.TokenID
	}
	if o.Transient != nil {
		out.Transient = *o.Transient
	}
	if o.UpdateTime != nil {
		out.UpdateTime = *o.UpdateTime
	}
	if o.Validity != nil {
		out.Validity = *o.Validity
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
func (o *SparseUserToken) GetCreateTime() (out time.Time) {

	if o.CreateTime == nil {
		return
	}

	return *o.CreateTime
}

// SetCreateTime sets the property CreateTime of the receiver using the address of the given value.
func (o *SparseUserToken) SetCreateTime(createTime time.Time) {

	o.CreateTime = &createTime
}

// GetNamespace returns the Namespace of the receiver.
func (o *SparseUserToken) GetNamespace() (out string) {

	if o.Namespace == nil {
		return
	}

	return *o.Namespace
}

// SetNamespace sets the property Namespace of the receiver using the address of the given value.
func (o *SparseUserToken) SetNamespace(namespace string) {

	o.Namespace = &namespace
}

// GetUpdateTime returns the UpdateTime of the receiver.
func (o *SparseUserToken) GetUpdateTime() (out time.Time) {

	if o.UpdateTime == nil {
		return
	}

	return *o.UpdateTime
}

// SetUpdateTime sets the property UpdateTime of the receiver using the address of the given value.
func (o *SparseUserToken) SetUpdateTime(updateTime time.Time) {

	o.UpdateTime = &updateTime
}

// GetZHash returns the ZHash of the receiver.
func (o *SparseUserToken) GetZHash() (out int) {

	if o.ZHash == nil {
		return
	}

	return *o.ZHash
}

// SetZHash sets the property ZHash of the receiver using the address of the given value.
func (o *SparseUserToken) SetZHash(zHash int) {

	o.ZHash = &zHash
}

// GetZone returns the Zone of the receiver.
func (o *SparseUserToken) GetZone() (out int) {

	if o.Zone == nil {
		return
	}

	return *o.Zone
}

// SetZone sets the property Zone of the receiver using the address of the given value.
func (o *SparseUserToken) SetZone(zone int) {

	o.Zone = &zone
}

// DeepCopy returns a deep copy if the SparseUserToken.
func (o *SparseUserToken) DeepCopy() *SparseUserToken {

	if o == nil {
		return nil
	}

	out := &SparseUserToken{}
	o.DeepCopyInto(out)

	return out
}

// DeepCopyInto copies the receiver into the given *SparseUserToken.
func (o *SparseUserToken) DeepCopyInto(out *SparseUserToken) {

	target, err := copystructure.Copy(o)
	if err != nil {
		panic(fmt.Sprintf("Unable to deepcopy SparseUserToken: %s", err))
	}

	*out = *target.(*SparseUserToken)
}

type mongoAttributesUserToken struct {
	ID             bson.ObjectId            `bson:"_id,omitempty"`
	Claims         []string                 `bson:"claims,omitempty"`
	ClientType     UserTokenClientTypeValue `bson:"clienttype"`
	CreateTime     time.Time                `bson:"createtime"`
	Email          string                   `bson:"email"`
	ExpirationDate time.Time                `bson:"expirationdate"`
	Name           string                   `bson:"name"`
	Namespace      string                   `bson:"namespace,omitempty"`
	SourceIP       string                   `bson:"sourceip"`
	TokenID        string                   `bson:"tokenid"`
	Transient      bool                     `bson:"transient,omitempty"`
	UpdateTime     time.Time                `bson:"updatetime"`
	ZHash          int                      `bson:"zhash"`
	Zone           int                      `bson:"zone"`
}
type mongoAttributesSparseUserToken struct {
	ID             bson.ObjectId             `bson:"_id,omitempty"`
	Claims         *[]string                 `bson:"claims,omitempty"`
	ClientType     *UserTokenClientTypeValue `bson:"clienttype,omitempty"`
	CreateTime     *time.Time                `bson:"createtime,omitempty"`
	Email          *string                   `bson:"email,omitempty"`
	ExpirationDate *time.Time                `bson:"expirationdate,omitempty"`
	Name           *string                   `bson:"name,omitempty"`
	Namespace      *string                   `bson:"namespace,omitempty"`
	SourceIP       *string                   `bson:"sourceip,omitempty"`
	TokenID        *string                   `bson:"tokenid,omitempty"`
	Transient      *bool                     `bson:"transient,omitempty"`
	UpdateTime     *time.Time                `bson:"updatetime,omitempty"`
	ZHash          *int                      `bson:"zhash,omitempty"`
	Zone           *int                      `bson:"zone,omitempty"`
}
