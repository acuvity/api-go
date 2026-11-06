package api

// Query types a DNS report counts lookups of, named as in the DNS RFCs.
const (
	DNSQueryTypeA          = "A"
	DNSQueryTypeAAAA       = "AAAA"
	DNSQueryTypeANY        = "ANY"
	DNSQueryTypeAXFR       = "AXFR"
	DNSQueryTypeCAA        = "CAA"
	DNSQueryTypeCDNSKEY    = "CDNSKEY"
	DNSQueryTypeCDS        = "CDS"
	DNSQueryTypeCERT       = "CERT"
	DNSQueryTypeCNAME      = "CNAME"
	DNSQueryTypeDNAME      = "DNAME"
	DNSQueryTypeDNSKEY     = "DNSKEY"
	DNSQueryTypeDS         = "DS"
	DNSQueryTypeHINFO      = "HINFO"
	DNSQueryTypeHTTPS      = "HTTPS"
	DNSQueryTypeIXFR       = "IXFR"
	DNSQueryTypeLOC        = "LOC"
	DNSQueryTypeMX         = "MX"
	DNSQueryTypeNAPTR      = "NAPTR"
	DNSQueryTypeNS         = "NS"
	DNSQueryTypeNSEC       = "NSEC"
	DNSQueryTypeNSEC3      = "NSEC3"
	DNSQueryTypeNSEC3PARAM = "NSEC3PARAM"
	DNSQueryTypeOPENPGPKEY = "OPENPGPKEY"
	DNSQueryTypePTR        = "PTR"
	DNSQueryTypeRRSIG      = "RRSIG"
	DNSQueryTypeSMIMEA     = "SMIMEA"
	DNSQueryTypeSOA        = "SOA"
	DNSQueryTypeSRV        = "SRV"
	DNSQueryTypeSSHFP      = "SSHFP"
	DNSQueryTypeSVCB       = "SVCB"
	DNSQueryTypeTLSA       = "TLSA"
	DNSQueryTypeTXT        = "TXT"
	DNSQueryTypeURI        = "URI"
)

var dnsQueryTypes = map[string]struct{}{
	DNSQueryTypeA:          {},
	DNSQueryTypeAAAA:       {},
	DNSQueryTypeANY:        {},
	DNSQueryTypeAXFR:       {},
	DNSQueryTypeCAA:        {},
	DNSQueryTypeCDNSKEY:    {},
	DNSQueryTypeCDS:        {},
	DNSQueryTypeCERT:       {},
	DNSQueryTypeCNAME:      {},
	DNSQueryTypeDNAME:      {},
	DNSQueryTypeDNSKEY:     {},
	DNSQueryTypeDS:         {},
	DNSQueryTypeHINFO:      {},
	DNSQueryTypeHTTPS:      {},
	DNSQueryTypeIXFR:       {},
	DNSQueryTypeLOC:        {},
	DNSQueryTypeMX:         {},
	DNSQueryTypeNAPTR:      {},
	DNSQueryTypeNS:         {},
	DNSQueryTypeNSEC:       {},
	DNSQueryTypeNSEC3:      {},
	DNSQueryTypeNSEC3PARAM: {},
	DNSQueryTypeOPENPGPKEY: {},
	DNSQueryTypePTR:        {},
	DNSQueryTypeRRSIG:      {},
	DNSQueryTypeSMIMEA:     {},
	DNSQueryTypeSOA:        {},
	DNSQueryTypeSRV:        {},
	DNSQueryTypeSSHFP:      {},
	DNSQueryTypeSVCB:       {},
	DNSQueryTypeTLSA:       {},
	DNSQueryTypeTXT:        {},
	DNSQueryTypeURI:        {},
}

// IsDNSQueryType reports whether t is a query type DNS reports count.
func IsDNSQueryType(t string) bool {
	_, ok := dnsQueryTypes[t]
	return ok
}
