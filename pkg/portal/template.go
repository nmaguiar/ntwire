package portal

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxTemplateInputSize bounds the size of a raw portal template (64 KB).
const MaxTemplateInputSize = 64 << 10

// MaxTemplateOutputSize bounds the rendered markdown output (1 MB).
const MaxTemplateOutputSize = 1 << 20

// MaxTemplateNesting bounds tag nesting depth to prevent stack exhaustion.
const MaxTemplateNesting = 16

// RenderTemplate evaluates a restricted Markdown template against a PortalContext.
func RenderTemplate(templateText string, ctx *PortalContext) (string, error) {
	if len(templateText) > MaxTemplateInputSize {
		return "", fmt.Errorf("portal template exceeds maximum size of %d bytes", MaxTemplateInputSize)
	}
	if ctx == nil {
		ctx = &PortalContext{}
	}

	scope := newRootScope(ctx)
	ast, err := parseTemplate(templateText)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	if err := ast.eval(scope, &sb, 0); err != nil {
		return "", err
	}

	res := sb.String()
	if len(res) > MaxTemplateOutputSize {
		return "", fmt.Errorf("rendered template exceeds maximum output size of %d bytes", MaxTemplateOutputSize)
	}
	return res, nil
}

// Scope provides scoped variable resolution for templates.
type Scope struct {
	parent *Scope
	data   map[string]any
	target *PortalTarget
}

func newRootScope(ctx *PortalContext) *Scope {
	m := make(map[string]any)

	// Portal metadata
	portalMap := map[string]any{
		"title":       ctx.Portal.Title,
		"description": ctx.Portal.Description,
		"version":     ctx.Portal.Version,
	}
	m["portal"] = portalMap

	// User metadata
	userMap := map[string]any{
		"identity":     ctx.User.Identity,
		"display_name": ctx.User.DisplayName,
		"method":       ctx.User.Method,
		"email":        ctx.User.Email,
		"groups":       ctx.User.Groups,
	}
	m["user"] = userMap

	// Client metadata
	clientMap := map[string]any{
		"os":             ctx.Client.OS,
		"arch":           ctx.Client.Arch,
		"hostname":       ctx.Client.Hostname,
		"client_version": ctx.Client.ClientVersion,
	}
	m["client"] = clientMap

	// Capabilities
	capsMap := map[string]any{
		"native_client":      ctx.Capabilities.NativeClient,
		"web_portal":         ctx.Capabilities.WebPortal,
		"open_socks_browser": ctx.Capabilities.OpenSocksBrowser,
		"copy":               ctx.Capabilities.Copy,
		"local_forward":      ctx.Capabilities.LocalForward,
		"ssh_launcher":       ctx.Capabilities.SSHLauncher,
	}
	m["capabilities"] = capsMap
	m["capability"] = capsMap

	// Custom variables
	varsMap := make(map[string]any, len(ctx.Variables))
	for k, v := range ctx.Variables {
		varsMap[k] = v
		// Also expose directly if no collision
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	m["variables"] = varsMap
	m["variable"] = varsMap

	// Filter categories: automatically drop empty categories
	var nonEmptyCats []PortalCategory
	for _, cat := range ctx.Categories {
		if len(cat.Targets) > 0 {
			nonEmptyCats = append(nonEmptyCats, cat)
		}
	}
	m["categories"] = nonEmptyCats
	m["targets"] = ctx.Targets

	return &Scope{data: m}
}

func (s *Scope) newChild(data map[string]any, target *PortalTarget) *Scope {
	return &Scope{
		parent: s,
		data:   data,
		target: target,
	}
}

func (s *Scope) lookup(path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")
	first := parts[0]
	var cur any

	// Target-specific handling (e.g. {{target.id}}, {{target.postgres}}, {{target.postgres.host}})
	if first == "target" {
		if s.target != nil {
			if len(parts) == 1 {
				return s.target, true
			}
			fieldVal := targetField(*s.target, parts[1])
			if fieldVal != nil {
				cur = fieldVal
				for i := 2; i < len(parts); i++ {
					cur = stepLookup(cur, parts[i])
					if cur == nil {
						return nil, false
					}
				}
				return cur, true
			}
			// Target ID matching: target.postgres or target.postgres.host
			wanted := strings.ToLower(parts[1])
			if strings.ToLower(s.target.ID) == wanted || strings.ToLower(s.target.Name) == wanted {
				if len(parts) == 2 {
					return true, true
				}
				// e.g. target.postgres.host
				cur = targetField(*s.target, parts[2])
				for i := 3; i < len(parts); i++ {
					cur = stepLookup(cur, parts[i])
					if cur == nil {
						return nil, false
					}
				}
				return cur, true
			}
			return false, true
		}

		// At root level with no current target
		if len(parts) >= 2 {
			wanted := strings.ToLower(parts[1])
			for curScope := s; curScope != nil; curScope = curScope.parent {
				if targets, ok := curScope.data["targets"].([]PortalTarget); ok {
					for _, t := range targets {
						if strings.ToLower(t.ID) == wanted || strings.ToLower(t.Name) == wanted {
							if len(parts) == 2 {
								return true, true
							}
							cur = targetField(t, parts[2])
							for i := 3; i < len(parts); i++ {
								cur = stepLookup(cur, parts[i])
								if cur == nil {
									return nil, false
								}
							}
							return cur, true
						}
					}
				}
			}
			return false, true
		}
	}

	// Search upward in scope stack
	found := false
	for curScope := s; curScope != nil; curScope = curScope.parent {
		if val, ok := curScope.data[first]; ok {
			cur = val
			found = true
			break
		}
	}

	if !found {
		return nil, false
	}

	// Traverse remaining parts
	for i := 1; i < len(parts); i++ {
		cur = stepLookup(cur, parts[i])
		if cur == nil {
			return nil, false
		}
	}

	return cur, true
}

func stepLookup(val any, key string) any {
	if val == nil {
		return nil
	}
	keyLower := strings.ToLower(key)
	switch v := val.(type) {
	case map[string]any:
		for k, item := range v {
			if strings.ToLower(k) == keyLower {
				return item
			}
		}
	case map[string]string:
		for k, item := range v {
			if strings.ToLower(k) == keyLower {
				return item
			}
		}
	case PortalTarget:
		return targetField(v, keyLower)
	case *PortalTarget:
		if v != nil {
			return targetField(*v, keyLower)
		}
	case PortalCategory:
		switch keyLower {
		case "name":
			return v.Name
		case "description":
			return v.Description
		case "targets":
			return v.Targets
		}
	case PortalUser:
		switch keyLower {
		case "identity":
			return v.Identity
		case "display_name":
			return v.DisplayName
		case "method":
			return v.Method
		case "email":
			return v.Email
		case "groups":
			return v.Groups
		}
	case PortalCapabilities:
		switch keyLower {
		case "native_client":
			return v.NativeClient
		case "web_portal":
			return v.WebPortal
		case "open_socks_browser":
			return v.OpenSocksBrowser
		case "copy":
			return v.Copy
		case "local_forward":
			return v.LocalForward
		case "ssh_launcher":
			return v.SSHLauncher
		}
	case PortalConnectionInfo:
		switch keyLower {
		case "socks":
			return v.Socks
		case "ssh":
			return v.SSH
		case "dbeaver":
			return v.DBeaver
		case "http":
			return v.HTTP
		}
	case *SocksConnectionInfo:
		if v != nil {
			switch keyLower {
			case "host":
				return v.Host
			case "port":
				return v.Port
			}
		}
	case *SSHConnectionInfo:
		if v != nil {
			switch keyLower {
			case "host":
				return v.Host
			case "port":
				return v.Port
			case "command":
				return v.Command
			}
		}
	case *DBeaverConnectionInfo:
		if v != nil {
			switch keyLower {
			case "host":
				return v.Host
			case "port":
				return v.Port
			case "socks_host":
				return v.SocksHost
			case "socks_port":
				return v.SocksPort
			}
		}
	case *HTTPConnectionInfo:
		if v != nil && keyLower == "url" {
			return v.URL
		}
	}
	return nil
}

func targetField(t PortalTarget, keyLower string) any {
	switch keyLower {
	case "id":
		return t.ID
	case "name":
		return t.Name
	case "description":
		return t.Description
	case "category":
		return t.Category
	case "icon":
		return t.Icon
	case "url":
		return t.URL
	case "target":
		return t.Target
	case "target_hint":
		return t.TargetHint
	case "host":
		return t.Host
	case "port":
		return t.Port
	case "protocol":
		return t.Protocol
	case "virtual_port":
		return t.VirtualPort
	case "local_port":
		return t.LocalPort
	case "local_host":
		return t.LocalHost
	case "local_address":
		return t.LocalAddress
	case "docs_url":
		return t.DocsURL
	case "instructions":
		return t.Instructions
	case "connection_instructions":
		return t.ConnectionInstructions
	case "is_socks":
		return t.IsSocks
	case "socks_tunnel":
		return t.SocksTunnel
	case "applications":
		return t.Applications
	case "connection":
		return t.Connection
	case "socks":
		return t.Connection.Socks
	case "ssh":
		return t.Connection.SSH
	case "dbeaver":
		return t.Connection.DBeaver
	}
	return nil
}

func isTruthy(val any) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return strings.TrimSpace(v) != ""
	case int:
		return v != 0
	case int64:
		return v != 0
	case uint64:
		return v != 0
	case []string:
		return len(v) > 0
	case []PortalTarget:
		return len(v) > 0
	case []PortalCategory:
		return len(v) > 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	case map[string]string:
		return len(v) > 0
	}
	return true
}

func formatValue(val any) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	default:
		return fmt.Sprint(v)
	}
}

// AST Nodes
type node interface {
	eval(s *Scope, sb *strings.Builder, depth int) error
}

type textNode struct {
	text string
}

func (n *textNode) eval(_ *Scope, sb *strings.Builder, _ int) error {
	sb.WriteString(n.text)
	return nil
}

type varNode struct {
	path string
}

func (n *varNode) eval(s *Scope, sb *strings.Builder, _ int) error {
	if val, ok := s.lookup(n.path); ok {
		sb.WriteString(formatValue(val))
	}
	return nil
}

type ifNode struct {
	condition string
	invert    bool
	thenBody  nodeList
	elseBody  nodeList
}

func (n *ifNode) eval(s *Scope, sb *strings.Builder, depth int) error {
	if depth > MaxTemplateNesting {
		return fmt.Errorf("template nesting exceeds limit of %d", MaxTemplateNesting)
	}

	val, found := s.lookup(n.condition)
	condTrue := found && isTruthy(val)
	if n.invert {
		condTrue = !condTrue
	}

	if condTrue {
		return n.thenBody.eval(s, sb, depth+1)
	} else if len(n.elseBody) > 0 {
		return n.elseBody.eval(s, sb, depth+1)
	}
	return nil
}

type eachNode struct {
	collectionPath string
	body           nodeList
}

func (n *eachNode) eval(s *Scope, sb *strings.Builder, depth int) error {
	if depth > MaxTemplateNesting {
		return fmt.Errorf("template nesting exceeds limit of %d", MaxTemplateNesting)
	}

	val, found := s.lookup(n.collectionPath)
	if !found || val == nil {
		return nil
	}

	switch col := val.(type) {
	case []PortalCategory:
		for _, cat := range col {
			if len(cat.Targets) == 0 {
				continue // Skip empty categories automatically
			}
			childData := map[string]any{
				"name":        cat.Name,
				"description": cat.Description,
				"targets":     cat.Targets,
			}
			childScope := s.newChild(childData, nil)
			if err := n.body.eval(childScope, sb, depth+1); err != nil {
				return err
			}
		}
	case []PortalTarget:
		for _, target := range col {
			targetCopy := target
			childData := targetToScopeMap(targetCopy)
			childScope := s.newChild(childData, &targetCopy)
			if err := n.body.eval(childScope, sb, depth+1); err != nil {
				return err
			}
		}
	case []string:
		for _, item := range col {
			childData := map[string]any{
				"this": item,
				"name": item,
			}
			childScope := s.newChild(childData, nil)
			if err := n.body.eval(childScope, sb, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func targetToScopeMap(t PortalTarget) map[string]any {
	return map[string]any{
		"id":                      t.ID,
		"name":                    t.Name,
		"description":             t.Description,
		"category":                t.Category,
		"icon":                    t.Icon,
		"url":                     t.URL,
		"target":                  t.Target,
		"target_hint":             t.TargetHint,
		"host":                    t.Host,
		"port":                    t.Port,
		"protocol":                t.Protocol,
		"virtual_port":            t.VirtualPort,
		"local_port":              t.LocalPort,
		"local_host":              t.LocalHost,
		"local_address":           t.LocalAddress,
		"docs_url":                t.DocsURL,
		"instructions":            t.Instructions,
		"connection_instructions": t.ConnectionInstructions,
		"is_socks":                t.IsSocks,
		"socks_tunnel":            t.SocksTunnel,
		"applications":            t.Applications,
		"connection":              t.Connection,
		"socks":                   t.Connection.Socks,
		"ssh":                     t.Connection.SSH,
		"dbeaver":                 t.Connection.DBeaver,
		"http":                    t.Connection.HTTP,
	}
}

type nodeList []node

func (nl nodeList) eval(s *Scope, sb *strings.Builder, depth int) error {
	for _, n := range nl {
		if err := n.eval(s, sb, depth); err != nil {
			return err
		}
	}
	return nil
}

// Parser
func parseTemplate(input string) (nodeList, error) {
	var nodes nodeList
	i := 0
	for i < len(input) {
		open := strings.Index(input[i:], "{{")
		if open < 0 {
			nodes = append(nodes, &textNode{text: input[i:]})
			break
		}
		if open > 0 {
			nodes = append(nodes, &textNode{text: input[i : i+open]})
			i += open
		}

		// Found {{
		closeIdx := strings.Index(input[i:], "}}")
		if closeIdx < 0 {
			return nil, fmt.Errorf("unclosed template tag at byte offset %d", i)
		}

		tagContent := strings.TrimSpace(input[i+2 : i+closeIdx])
		tagLen := closeIdx + 2

		if strings.HasPrefix(tagContent, "#if ") {
			cond := strings.TrimSpace(strings.TrimPrefix(tagContent, "#if "))
			thenNodes, elseNodes, consumed, err := parseIfBlock(input[i+tagLen:], "if")
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, &ifNode{condition: cond, thenBody: thenNodes, elseBody: elseNodes})
			i += tagLen + consumed
			continue
		}

		if strings.HasPrefix(tagContent, "#unless ") {
			cond := strings.TrimSpace(strings.TrimPrefix(tagContent, "#unless "))
			thenNodes, elseNodes, consumed, err := parseIfBlock(input[i+tagLen:], "unless")
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, &ifNode{condition: cond, invert: true, thenBody: thenNodes, elseBody: elseNodes})
			i += tagLen + consumed
			continue
		}

		if strings.HasPrefix(tagContent, "#each ") {
			colPath := strings.TrimSpace(strings.TrimPrefix(tagContent, "#each "))
			body, consumed, err := parseEachBlock(input[i+tagLen:])
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, &eachNode{collectionPath: colPath, body: body})
			i += tagLen + consumed
			continue
		}

		if strings.HasPrefix(tagContent, "/") || tagContent == "else" {
			return nil, fmt.Errorf("unexpected tag {{%s}} at byte offset %d", tagContent, i)
		}

		// Simple variable substitution
		nodes = append(nodes, &varNode{path: tagContent})
		i += tagLen
	}
	return nodes, nil
}

func parseIfBlock(input string, kind string) (thenBody nodeList, elseBody nodeList, consumed int, err error) {
	endTag := "/if"
	if kind == "unless" {
		endTag = "/unless"
	}

	i := 0
	inElse := false

	for i < len(input) {
		open := strings.Index(input[i:], "{{")
		if open < 0 {
			return nil, nil, 0, fmt.Errorf("unclosed {{#%s}} block", kind)
		}
		if open > 0 {
			target := &thenBody
			if inElse {
				target = &elseBody
			}
			*target = append(*target, &textNode{text: input[i : i+open]})
			i += open
		}

		closeIdx := strings.Index(input[i:], "}}")
		if closeIdx < 0 {
			return nil, nil, 0, fmt.Errorf("unclosed template tag in {{#%s}} block", kind)
		}

		tagContent := strings.TrimSpace(input[i+2 : i+closeIdx])
		tagLen := closeIdx + 2

		if tagContent == endTag {
			return thenBody, elseBody, i + tagLen, nil
		}

		if tagContent == "else" {
			if inElse {
				return nil, nil, 0, fmt.Errorf("duplicate {{else}} inside {{#%s}} block", kind)
			}
			inElse = true
			i += tagLen
			continue
		}

		if strings.HasPrefix(tagContent, "#if ") {
			subCond := strings.TrimSpace(strings.TrimPrefix(tagContent, "#if "))
			subThen, subElse, subConsumed, err := parseIfBlock(input[i+tagLen:], "if")
			if err != nil {
				return nil, nil, 0, err
			}
			target := &thenBody
			if inElse {
				target = &elseBody
			}
			*target = append(*target, &ifNode{condition: subCond, thenBody: subThen, elseBody: subElse})
			i += tagLen + subConsumed
			continue
		}

		if strings.HasPrefix(tagContent, "#unless ") {
			subCond := strings.TrimSpace(strings.TrimPrefix(tagContent, "#unless "))
			subThen, subElse, subConsumed, err := parseIfBlock(input[i+tagLen:], "unless")
			if err != nil {
				return nil, nil, 0, err
			}
			target := &thenBody
			if inElse {
				target = &elseBody
			}
			*target = append(*target, &ifNode{condition: subCond, invert: true, thenBody: subThen, elseBody: subElse})
			i += tagLen + subConsumed
			continue
		}

		if strings.HasPrefix(tagContent, "#each ") {
			colPath := strings.TrimSpace(strings.TrimPrefix(tagContent, "#each "))
			subBody, subConsumed, err := parseEachBlock(input[i+tagLen:])
			if err != nil {
				return nil, nil, 0, err
			}
			target := &thenBody
			if inElse {
				target = &elseBody
			}
			*target = append(*target, &eachNode{collectionPath: colPath, body: subBody})
			i += tagLen + subConsumed
			continue
		}

		target := &thenBody
		if inElse {
			target = &elseBody
		}
		*target = append(*target, &varNode{path: tagContent})
		i += tagLen
	}

	return nil, nil, 0, fmt.Errorf("unclosed {{#%s}} block", kind)
}

func parseEachBlock(input string) (body nodeList, consumed int, err error) {
	i := 0
	for i < len(input) {
		open := strings.Index(input[i:], "{{")
		if open < 0 {
			return nil, 0, fmt.Errorf("unclosed {{#each}} block")
		}
		if open > 0 {
			body = append(body, &textNode{text: input[i : i+open]})
			i += open
		}

		closeIdx := strings.Index(input[i:], "}}")
		if closeIdx < 0 {
			return nil, 0, fmt.Errorf("unclosed template tag in {{#each}} block")
		}

		tagContent := strings.TrimSpace(input[i+2 : i+closeIdx])
		tagLen := closeIdx + 2

		if tagContent == "/each" {
			return body, i + tagLen, nil
		}

		if strings.HasPrefix(tagContent, "#if ") {
			subCond := strings.TrimSpace(strings.TrimPrefix(tagContent, "#if "))
			subThen, subElse, subConsumed, err := parseIfBlock(input[i+tagLen:], "if")
			if err != nil {
				return nil, 0, err
			}
			body = append(body, &ifNode{condition: subCond, thenBody: subThen, elseBody: subElse})
			i += tagLen + subConsumed
			continue
		}

		if strings.HasPrefix(tagContent, "#unless ") {
			subCond := strings.TrimSpace(strings.TrimPrefix(tagContent, "#unless "))
			subThen, subElse, subConsumed, err := parseIfBlock(input[i+tagLen:], "unless")
			if err != nil {
				return nil, 0, err
			}
			body = append(body, &ifNode{condition: subCond, invert: true, thenBody: subThen, elseBody: subElse})
			i += tagLen + subConsumed
			continue
		}

		if strings.HasPrefix(tagContent, "#each ") {
			colPath := strings.TrimSpace(strings.TrimPrefix(tagContent, "#each "))
			subBody, subConsumed, err := parseEachBlock(input[i+tagLen:])
			if err != nil {
				return nil, 0, err
			}
			body = append(body, &eachNode{collectionPath: colPath, body: subBody})
			i += tagLen + subConsumed
			continue
		}

		body = append(body, &varNode{path: tagContent})
		i += tagLen
	}

	return nil, 0, fmt.Errorf("unclosed {{#each}} block")
}
