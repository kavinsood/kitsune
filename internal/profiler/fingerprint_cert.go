package profiler

// checkCertIssuer matches the certificate issuer against fingerprint patterns
// This is a dedicated function for the TLS certificate issuer vector
func (s *Wappalyze) checkCertIssuer(issuer string) []matchPartResult {
	if issuer == "" {
		return nil
	}
	
	// Use the existing matchString function with the certIssuerPart type
	return s.fingerprints.matchString(issuer, certIssuerPart, s.regexTimeout)
}