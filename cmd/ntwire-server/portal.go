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
		os.Exit(2)
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
	case "help":
		if len(subArgs) > 0 {
			switch subArgs[0] {
			case "describe":
				runPortalDescribe([]string{"-h"}, u)
			case "prompt":
				runPortalPrompt([]string{"-h"}, u)
			case "validate":
				runPortalValidate([]string{"-h"}, u)
			case "render":
				runPortalRender([]string{"-h"}, u)
			default:
				printPortalHelp(u)
				os.Exit(2)
			}
			return
		}
		printPortalHelp(u)
		os.Exit(0)
	case "-h", "--help":
		printPortalHelp(u)
		os.Exit(0)
	default:
		u.Errorf("unknown portal command: %s", cmd)
		printPortalHelp(u)
		os.Exit(2)
	}
}

func printPortalHelp(u *ui.UI) {
	ui.Spec{
		Tool:    "ntwire-server portal",
		Tagline: "portal template inspection, prompt generation, validation, and rendering",
		Commands: []ui.Command{
			{Name: "describe", Summary: "print machine-readable schema descriptor JSON"},
			{Name: "prompt", Summary: "generate sanitized LLM prompt for portal authoring"},
			{Name: "validate", Summary: "validate template syntax, safety, and target references"},
			{Name: "render", Summary: "render template against configured targets"},
		},
		Examples: []string{
			"ntwire-server portal describe",
			"ntwire-server portal prompt -config ntwire.yaml",
			"ntwire-server portal validate -config ntwire.yaml",
			"ntwire-server portal render -config ntwire.yaml",
			"ntwire-server portal <command> -h",
		},
	}.Fprint(u.Err, u)
}

func runPortalDescribe(args []string, u *ui.UI) {
	fs := flag.NewFlagSet("portal describe", flag.ExitOnError)
	configPath := fs.String("config", "", "optional server configuration file")
	indent := fs.Bool("indent", true, "pretty-print JSON output")
	fs.Usage = func() {
		ui.Spec{
			Tool:     "ntwire-server portal describe",
			Tagline:  "print machine-readable schema descriptor JSON",
			Flags:    ui.FlagsOf(fs),
			Examples: []string{"ntwire-server portal describe", "ntwire-server portal describe -config ntwire.yaml", "ntwire-server portal describe -indent=false"},
		}.Fprint(u.Err, u)
	}
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
	fs.Usage = func() {
		ui.Spec{
			Tool:     "ntwire-server portal prompt",
			Tagline:  "generate sanitized LLM prompt for portal authoring",
			Flags:    ui.FlagsOf(fs),
			Examples: []string{"ntwire-server portal prompt", "ntwire-server portal prompt -config ntwire.yaml"},
		}.Fprint(u.Err, u)
	}
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
	fs.Usage = func() {
		ui.Spec{
			Tool:     "ntwire-server portal validate",
			Tagline:  "validate template syntax, safety, and target references",
			Flags:    ui.FlagsOf(fs),
			Examples: []string{"ntwire-server portal validate -config ntwire.yaml", "ntwire-server portal validate -template portal.md", "ntwire-server portal validate -config ntwire.yaml -template portal.md"},
		}.Fprint(u.Err, u)
	}
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
	fs.Usage = func() {
		ui.Spec{
			Tool:     "ntwire-server portal render",
			Tagline:  "render template against configured targets",
			Flags:    ui.FlagsOf(fs),
			Examples: []string{"ntwire-server portal render -config ntwire.yaml", "ntwire-server portal render -config ntwire.yaml -format html", "ntwire-server portal render -config ntwire.yaml -template custom.md"},
		}.Fprint(u.Err, u)
	}
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
