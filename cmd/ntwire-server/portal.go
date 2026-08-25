package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nmaguiar/ntwire/pkg/portal"
	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func runPortal(args []string, u *ui.UI) {
	if len(args) == 0 {
		printPortalHelp(u)
		os.Exit(1)
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "describe":
		runPortalDescribe(subArgs, u)
	case "prompt":
		runPortalPrompt(subArgs, u)
	case "validate":
		runPortalValidate(subArgs, u)
	case "render":
		runPortalRender(subArgs, u)
	case "help", "-h", "--help":
		printPortalHelp(u)
		os.Exit(0)
	default:
		u.Errorf("unknown portal command: %s", cmd)
		printPortalHelp(u)
		os.Exit(1)
	}
}

func printPortalHelp(u *ui.UI) {
	fmt.Fprintf(u.Err, `ntwire-server portal commands:

  describe    Print machine-readable schema descriptor JSON
  prompt      Generate sanitized LLM prompt for portal authoring
  validate    Validate template syntax, safety, and target references
  render      Render template against configured targets

Run 'ntwire-server portal <command> -h' for command-specific flags.
`)
}

func runPortalDescribe(args []string, u *ui.UI) {
	fs := flag.NewFlagSet("portal describe", flag.ExitOnError)
	configPath := fs.String("config", "", "optional server configuration file")
	indent := fs.Bool("indent", true, "pretty-print JSON output")
	_ = fs.Parse(args)

	var portalCfg portal.PortalConfig
	var targetInfos []portal.TargetInfo

	if *configPath != "" {
		if c, err := server.LoadConfig(*configPath); err == nil {
			portalCfg = c.Portal
			for _, t := range c.Tunnels {
				targetInfos = append(targetInfos, portal.TargetInfo{
					Name:         t.Name,
					Target:       t.Target,
					Description:  t.Description,
					VirtualPort:  t.VirtualPort,
					LocalPort:    t.LocalPort,
					LocalHost:    t.LocalHost,
					Instructions: t.Instructions,
					DocsURL:      t.DocsURL,
					IsSocks:      t.IsSocks(),
					Portal:       t.Portal,
				})
			}
		}
	}

	desc := portal.Describe(portalCfg, targetInfos)
	var b []byte
	var err error
	if *indent {
		b, err = json.MarshalIndent(desc, "", "  ")
	} else {
		b, err = json.Marshal(desc)
	}
	if err != nil {
		u.Errorf("describe: %v", err)
		os.Exit(1)
	}
	fmt.Fprintln(u.Out, string(b))
}

func runPortalPrompt(args []string, u *ui.UI) {
	fs := flag.NewFlagSet("portal prompt", flag.ExitOnError)
	configPath := fs.String("config", "ntwire.yaml", "server configuration file")
	_ = fs.Parse(args)

	c, err := server.LoadConfig(*configPath)
	if err != nil {
		u.Errorf("configuration error: %v", err)
		os.Exit(2)
	}

	var targetInfos []portal.TargetInfo
	for _, t := range c.Tunnels {
		targetInfos = append(targetInfos, portal.TargetInfo{
			Name:         t.Name,
			Target:       t.Target,
			Description:  t.Description,
			VirtualPort:  t.VirtualPort,
			LocalPort:    t.LocalPort,
			LocalHost:    t.LocalHost,
			Instructions: t.Instructions,
			DocsURL:      t.DocsURL,
			IsSocks:      t.IsSocks(),
			Portal:       t.Portal,
		})
	}

	prompt := portal.GenerateLLMPrompt(c.Portal, targetInfos)
	fmt.Fprintln(u.Out, prompt)
}

func runPortalValidate(args []string, u *ui.UI) {
	fs := flag.NewFlagSet("portal validate", flag.ExitOnError)
	configPath := fs.String("config", "ntwire.yaml", "server configuration file")
	templatePath := fs.String("template", "", "template file to validate (overrides config)")
	_ = fs.Parse(args)

	var templateContent string
	knownCtx := &portal.KnownContext{
		Variables:    map[string]string{},
		TargetIDs:    map[string]bool{},
		Capabilities: portal.DefaultCapabilities(),
	}

	if *templatePath != "" {
		b, err := os.ReadFile(*templatePath)
		if err != nil {
			u.Errorf("cannot read template file %s: %v", *templatePath, err)
			os.Exit(1)
		}
		templateContent = string(b)
	}

	// Try loading config to get known targets/variables and/or template if not provided via -template
	c, err := server.LoadConfig(*configPath)
	if err == nil {
		for _, t := range c.Tunnels {
			knownCtx.TargetIDs[t.Name] = true
		}
		for k, v := range c.Portal.Variables {
			knownCtx.Variables[k] = v
		}
		if templateContent == "" {
			templateContent = c.Portal.Template
		}
	} else if *templatePath == "" {
		u.Errorf("configuration error: %v (specify -template to validate standalone template)", err)
		os.Exit(2)
	}

	if templateContent == "" {
		templateContent = portal.DefaultTemplate
	}

	errs := portal.ValidateTemplate(templateContent, knownCtx)
	if len(errs) == 0 {
		u.Success("Portal template is valid.")
		return
	}

	hasFatal := false
	for _, e := range errs {
		if e.Fatal {
			hasFatal = true
			u.Errorf("Line %d: %s", e.Line, e.Message)
		} else {
			u.Warn("Line %d: %s", e.Line, e.Message)
		}
	}

	if hasFatal {
		os.Exit(1)
	}
}

func runPortalRender(args []string, u *ui.UI) {
	fs := flag.NewFlagSet("portal render", flag.ExitOnError)
	configPath := fs.String("config", "ntwire.yaml", "server configuration file")
	templatePath := fs.String("template", "", "template file to render (overrides config)")
	userName := fs.String("user", "sample-user", "username for portal context")
	mode := fs.String("mode", "native", "portal mode: native or wireguard")
	format := fs.String("format", "markdown", "output format: markdown, html, full-html, or json")
	_ = fs.Parse(args)

	c, err := server.LoadConfig(*configPath)
	if err != nil {
		u.Errorf("configuration error: %v", err)
		os.Exit(2)
	}

	var targetInfos []portal.TargetInfo
	for _, t := range c.Tunnels {
		targetInfos = append(targetInfos, portal.TargetInfo{
			Name:         t.Name,
			Target:       t.Target,
			Description:  t.Description,
			VirtualPort:  t.VirtualPort,
			LocalPort:    t.LocalPort,
			LocalHost:    t.LocalHost,
			Instructions: t.Instructions,
			DocsURL:      t.DocsURL,
			IsSocks:      t.IsSocks(),
			Portal:       t.Portal,
		})
	}

	templateContent := c.Portal.Template
	if *templatePath != "" {
		b, err := os.ReadFile(*templatePath)
		if err != nil {
			u.Errorf("cannot read template file %s: %v", *templatePath, err)
			os.Exit(1)
		}
		templateContent = string(b)
	}
	if templateContent == "" {
		templateContent = portal.DefaultTemplate
	}

	portalCtx := portal.BuildContext(
		c.Portal,
		portal.PortalUser{
			Identity:    *userName,
			DisplayName: *userName,
			Method:      "cli",
		},
		portal.PortalClient{},
		targetInfos,
		*mode,
		"100.64.0.1",
	)

	renderedMD, err := portal.RenderTemplate(templateContent, portalCtx)
	if err != nil {
		u.Errorf("render error: %v", err)
		os.Exit(1)
	}

	renderedHTML := portal.RenderMarkdown(renderedMD, portalCtx.Capabilities)

	switch strings.ToLower(*format) {
	case "markdown", "md":
		fmt.Fprintln(u.Out, renderedMD)
	case "html":
		fmt.Fprintln(u.Out, renderedHTML)
	case "full-html", "page":
		fmt.Fprintln(u.Out, portal.WrapWebPage(portalCtx.Portal.Title, renderedHTML))
	case "json":
		payload := portal.RenderedPortal{
			Title:    portalCtx.Portal.Title,
			Markdown: renderedMD,
			HTML:     renderedHTML,
			Context:  portalCtx,
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Fprintln(u.Out, string(b))
	default:
		u.Errorf("unknown format %q (supported: markdown, html, full-html, json)", *format)
		os.Exit(1)
	}
}
