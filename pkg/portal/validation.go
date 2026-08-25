package portal

import (
	"fmt"
	"strings"
)

// ValidationError describes an issue discovered during template validation.
type ValidationError struct {
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

func (e ValidationError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Message)
	}
	return e.Message
}

// KnownContext describes known variable names and targets for validation.
type KnownContext struct {
	Variables    map[string]string
	TargetIDs    map[string]bool
	Capabilities map[string]bool
}

// DefaultCapabilities returns the set of valid ntwire capability names.
func DefaultCapabilities() map[string]bool {
	return map[string]bool{
		"native_client":      true,
		"web_portal":         true,
		"open_socks_browser": true,
		"copy":               true,
		"local_forward":      true,
		"ssh_launcher":       true,
	}
}

// ValidateTemplate checks a portal markdown template for syntax errors, unknown variables/targets, and security violations.
func ValidateTemplate(templateText string, known *KnownContext) []ValidationError {
	var errs []ValidationError

	if len(templateText) > MaxTemplateInputSize {
		errs = append(errs, ValidationError{
			Message: fmt.Sprintf("template exceeds maximum size of %d bytes (got %d)", MaxTemplateInputSize, len(templateText)),
			Fatal:   true,
		})
	}

	lines := strings.Split(templateText, "\n")

	// 1. Security check: prohibit dangerous schemes and raw script tags
	for lineNum, line := range lines {
		lNum := lineNum + 1
		lineLower := strings.ToLower(line)

		if strings.Contains(lineLower, "<script") || strings.Contains(lineLower, "</script>") {
			errs = append(errs, ValidationError{
				Line:    lNum,
				Message: "raw <script> tags are strictly forbidden in portal templates",
				Fatal:   true,
			})
		}
		if strings.Contains(lineLower, "javascript:") {
			errs = append(errs, ValidationError{
				Line:    lNum,
				Message: "dangerous URI scheme 'javascript:' is forbidden",
				Fatal:   true,
			})
		}
		if strings.Contains(lineLower, "data:text/html") {
			errs = append(errs, ValidationError{
				Line:    lNum,
				Message: "dangerous URI scheme 'data:text/html' is forbidden",
				Fatal:   true,
			})
		}
		if strings.Contains(lineLower, "onload=") || strings.Contains(lineLower, "onerror=") || strings.Contains(lineLower, "onclick=") {
			errs = append(errs, ValidationError{
				Line:    lNum,
				Message: "inline JavaScript event handlers are forbidden",
				Fatal:   true,
			})
		}

		// Action URI validation
		if strings.Contains(line, "ntwire://") {
			for _, part := range strings.Fields(line) {
				idx := strings.Index(part, "ntwire://")
				if idx >= 0 {
					cleanURI := strings.Trim(part[idx:], "()[]\"'<>")
					action, targetID, err := ParseActionURI(cleanURI)
					if err != nil {
						errs = append(errs, ValidationError{
							Line:    lNum,
							Message: fmt.Sprintf("invalid ntwire action URI %q: %v", cleanURI, err),
							Fatal:   false,
						})
					} else if known != nil && len(known.TargetIDs) > 0 && !known.TargetIDs[targetID] && targetID != "{{id}}" && !strings.HasPrefix(targetID, "{{") {
						errs = append(errs, ValidationError{
							Line:    lNum,
							Message: fmt.Sprintf("action %s references unknown target ID %q", action, targetID),
							Fatal:   false,
						})
					}
				}
			}
		}
	}

	// 2. Syntax validation via parseTemplate
	_, parseErr := parseTemplate(templateText)
	if parseErr != nil {
		errs = append(errs, ValidationError{
			Message: fmt.Sprintf("template syntax error: %v", parseErr),
			Fatal:   true,
		})
	}

	return errs
}
