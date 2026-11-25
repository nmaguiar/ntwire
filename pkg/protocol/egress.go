package protocol

import "regexp"

var egressClassPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidEgressClass validates a server-declared destination policy label.
func ValidEgressClass(s string) bool { return egressClassPattern.MatchString(s) }
