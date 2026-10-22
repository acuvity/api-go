package api

import (
	"strconv"
	"strings"
)

// Name is the name of a capability: something a deployment can do, and an agent can implement.
type CapabilityName string

const (
	// CapabilityGateway is for the Apex proxy/gateway.
	CapabilityGateway CapabilityName = "Gateway"

	// CapabilityDiscovery is for the Perrin discovery agent.
	CapabilityDiscovery CapabilityName = "Discovery"
)

// Separator joins a capability and its version, as in "Discovery-1".
const Separator = "-"

// CapabilitySupported builds what an agent reports, and sends when it fetches its conf,
// for a capability it implements: the name followed by the version of that
// capability it supports.
func CapabilitySupported(n CapabilityName, version uint) string {
	return string(n) + Separator + strconv.FormatUint(uint64(version), 10)
}

// CapabilityParse splits a reported capability into its name and version. A value with
// no valid version, such as a plain deployment capability, returns the whole
// value as the name and version 0.
func CapabilityParse(s string) (name CapabilityName, version uint) {

	i := strings.LastIndex(s, Separator)
	if i < 0 {
		return CapabilityName(s), 0
	}

	v, err := strconv.ParseUint(s[i+len(Separator):], 10, strconv.IntSize)
	if err != nil {
		return CapabilityName(s), 0
	}

	return CapabilityName(s[:i]), uint(v)
}
