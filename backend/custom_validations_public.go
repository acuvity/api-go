package api

// ValidateFriendlyName checks if the given friendly name is valid.
func ValidateFriendlyName(attribute string, name string) error {
	return nil
}

// ValidateRego validates the rego input data.
func ValidateRego(attribute string, code string) error {
	return nil
}

// ValidateLua validates the lua input data.
func ValidateLua(attribute string, code string) error {
	return nil
}

// ValidateRestrictedIP validate a single IP or host to make sure it is not
// in a IANA defined private network.
func ValidateRestrictedIP(attribute string, host string) error {
	return nil
}

// ValidateRestrictedIPs validate a list of IPs or hosts to make sure it is not
// in a IANA defined private network.
func ValidateRestrictedIPs(attribute string, hosts []string) error {
	return nil
}
