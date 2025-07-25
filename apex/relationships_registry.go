// Code generated by elegen. DO NOT EDIT.
// Source: go.acuvity.ai/elemental (templates/relationships_registry.gotpl)

package api

import "go.acuvity.ai/elemental"

var relationshipsRegistry elemental.RelationshipsRegistry

func init() {

	relationshipsRegistry = elemental.RelationshipsRegistry{}

	relationshipsRegistry[AnalyzerIdentity] = &elemental.Relationship{
		RetrieveMany: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
		Info: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
	}

	relationshipsRegistry[LatencyIdentity] = &elemental.Relationship{}

	relationshipsRegistry[PoliceRequestIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
	}

	relationshipsRegistry[PoliceResponseIdentity] = &elemental.Relationship{}

	relationshipsRegistry[PrincipalIdentity] = &elemental.Relationship{}

	relationshipsRegistry[PrincipalAppIdentity] = &elemental.Relationship{}

	relationshipsRegistry[PrincipalAppUserIdentity] = &elemental.Relationship{}

	relationshipsRegistry[PrincipalUserIdentity] = &elemental.Relationship{}

	relationshipsRegistry[RootIdentity] = &elemental.Relationship{}

	relationshipsRegistry[ScanRequestIdentity] = &elemental.Relationship{
		Create: map[string]*elemental.RelationshipInfo{
			"root": {},
		},
	}

	relationshipsRegistry[ScanResponseIdentity] = &elemental.Relationship{}

	relationshipsRegistry[TraceRefIdentity] = &elemental.Relationship{}

}
