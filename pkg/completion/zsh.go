package completion

import (
	"fmt"
	"io"
	"strings"
)

// Zsh generates a zsh completion script for cmd.
func Zsh(cmd Command, w io.Writer) error {
	funcName := "_" + sanitizeFuncName(cmd.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "#compdef %s\n\n", cmd.Name)
	fmt.Fprintf(&b, "%s() {\n", funcName)

	if len(cmd.Subcommands) > 0 {
		b.WriteString(`    local context state state_policy line
    typeset -A opt_args

    local -a subcommands
    subcommands=(
`)
		for _, sc := range cmd.Subcommands {
			desc := escapeZshDesc(sc.Summary)
			if desc == "" {
				desc = sc.Name
			}
			fmt.Fprintf(&b, "        '%s:%s'\n", sc.Name, desc)
		}
		b.WriteString("    )\n\n    _arguments -C \\\n")

		for _, f := range cmd.Flags {
			fmt.Fprintf(&b, "        %s \\\n", zshFlagSpec(f))
		}
		b.WriteString(`        '(-h --help)'{-h,--help}'[show help]' \
        '1:command:->command' \
        '*::arg:->args'

    case $state in
        command)
            _describe 'command' subcommands
            ;;
        args)
            case $line[1] in
`)
		for _, sc := range cmd.Subcommands {
			fmt.Fprintf(&b, "                %s)\n", sc.Name)
			b.WriteString("                    _arguments \\\n")
			for _, f := range sc.Flags {
				fmt.Fprintf(&b, "                        %s \\\n", zshFlagSpec(f))
			}
			b.WriteString("                        '(-h --help)'{-h,--help}'[show help]'")
			if len(sc.ArgChoices) > 0 {
				fmt.Fprintf(&b, " \\\n                        '1:arg:(%s)'", strings.Join(sc.ArgChoices, " "))
			}
			b.WriteString("\n                    ;;\n")
		}
		b.WriteString(`            esac
            ;;
    esac
`)
	} else {
		b.WriteString("    _arguments \\\n")
		for _, f := range cmd.Flags {
			fmt.Fprintf(&b, "        %s \\\n", zshFlagSpec(f))
		}
		b.WriteString(`        '(-h --help)'{-h,--help}'[show help]' \
        '1:shell:(bash zsh fish powershell)'
`)
	}

	fmt.Fprintf(&b, "}\n\ncompdef %s %s\n", funcName, cmd.Name)
	_, err := io.WriteString(w, b.String())
	return err
}

func zshFlagSpec(f Flag) string {
	desc := escapeZshDesc(f.Usage)
	if desc == "" {
		desc = f.Name
	}
	if !f.TakesValue {
		return fmt.Sprintf("'(-%s --%s)'{-%s,--%s}'[%s]'", f.Name, f.Name, f.Name, f.Name, desc)
	}
	if len(f.Choices) > 0 {
		return fmt.Sprintf("'(-%s --%s)'{-%s,--%s}'[%s]:choice:(%s)'", f.Name, f.Name, f.Name, f.Name, desc, strings.Join(f.Choices, " "))
	}
	if f.IsFilePath {
		return fmt.Sprintf("'(-%s --%s)'{-%s,--%s}'[%s]:file:_files'", f.Name, f.Name, f.Name, f.Name, desc)
	}
	return fmt.Sprintf("'(-%s --%s)'{-%s,--%s}'[%s]:value:'", f.Name, f.Name, f.Name, f.Name, desc)
}

func escapeZshDesc(s string) string {
	s = strings.ReplaceAll(s, "'", `'\''`)
	s = strings.ReplaceAll(s, "[", `\[`)
	s = strings.ReplaceAll(s, "]", `\]`)
	s = strings.ReplaceAll(s, ":", `\:`)
	return s
}
