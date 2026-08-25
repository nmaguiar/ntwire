package completion

import (
	"fmt"
	"io"
	"strings"
)

// Bash generates a bash completion script for cmd.
func Bash(cmd Command, w io.Writer) error {
	funcName := "_" + sanitizeFuncName(cmd.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "# bash completion for %s -*- shell-script -*-\n\n", cmd.Name)
	fmt.Fprintf(&b, "%s() {\n", funcName)
	b.WriteString(`    local cur prev words cword
    if type _init_completion >/dev/null 2>&1; then
        _init_completion -n : || return
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

`)

	if len(cmd.Subcommands) > 0 {
		var subcmdNames []string
		for _, sc := range cmd.Subcommands {
			subcmdNames = append(subcmdNames, sc.Name)
		}
		subcmdsStr := strings.Join(subcmdNames, " ")

		fmt.Fprintf(&b, "    local subcommands=%q\n", subcmdsStr)
		b.WriteString(`    local subcmd=""
    local i=1

    while [[ $i -lt $cword ]]; do
        local w="${words[i]}"
        case "$w" in
`)
		fmt.Fprintf(&b, "            %s)\n", strings.Join(subcmdNames, "|"))
		b.WriteString(`                subcmd="$w"
                break
                ;;
        esac
        ((i++))
    done

    if [[ -z "$subcmd" ]]; then
`)
		hasPrevCases := false
		for _, f := range cmd.Flags {
			if len(f.Choices) > 0 || f.IsFilePath {
				if !hasPrevCases {
					b.WriteString("        case \"$prev\" in\n")
					hasPrevCases = true
				}
				fmt.Fprintf(&b, "            -%s|--%s)\n", f.Name, f.Name)
				if len(f.Choices) > 0 {
					fmt.Fprintf(&b, "                COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(f.Choices, " "))
				} else if f.IsFilePath {
					b.WriteString("                COMPREPLY=( $(compgen -f -- \"$cur\") )\n")
				}
				b.WriteString("                return 0\n                ;;\n")
			}
		}
		if hasPrevCases {
			b.WriteString("        esac\n\n")
		}

		var topFlags []string
		for _, f := range cmd.Flags {
			topFlags = append(topFlags, "-"+f.Name, "--"+f.Name)
		}
		topFlags = append(topFlags, "-h", "--help")

		b.WriteString(`        if [[ "$cur" == -* ]]; then
`)
		fmt.Fprintf(&b, "            COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(topFlags, " "))
		b.WriteString(`            return 0
        fi
        COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        return 0
    fi

    case "$subcmd" in
`)
		for _, sc := range cmd.Subcommands {
			fmt.Fprintf(&b, "        %s)\n", sc.Name)
			hasPrevCases := false
			for _, f := range sc.Flags {
				if len(f.Choices) > 0 || f.IsFilePath {
					if !hasPrevCases {
						b.WriteString("            case \"$prev\" in\n")
						hasPrevCases = true
					}
					fmt.Fprintf(&b, "                -%s|--%s)\n", f.Name, f.Name)
					if len(f.Choices) > 0 {
						fmt.Fprintf(&b, "                    COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(f.Choices, " "))
					} else if f.IsFilePath {
						b.WriteString("                    COMPREPLY=( $(compgen -f -- \"$cur\") )\n")
					}
					b.WriteString("                    return 0\n                    ;;\n")
				}
			}
			if hasPrevCases {
				b.WriteString("            esac\n")
			}

			var scFlags []string
			for _, f := range sc.Flags {
				scFlags = append(scFlags, "-"+f.Name, "--"+f.Name)
			}
			scFlags = append(scFlags, "-h", "--help")

			b.WriteString("            if [[ \"$cur\" == -* ]]; then\n")
			fmt.Fprintf(&b, "                COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(scFlags, " "))
			b.WriteString("                return 0\n            fi\n")

			if len(sc.ArgChoices) > 0 {
				fmt.Fprintf(&b, "            COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(sc.ArgChoices, " "))
				b.WriteString("            return 0\n")
			}

			b.WriteString("            ;;\n")
		}
		b.WriteString("    esac\n")
	} else {
		hasPrevCases := false
		for _, f := range cmd.Flags {
			if len(f.Choices) > 0 || f.IsFilePath {
				if !hasPrevCases {
					b.WriteString("    case \"$prev\" in\n")
					hasPrevCases = true
				}
				fmt.Fprintf(&b, "        -%s|--%s)\n", f.Name, f.Name)
				if len(f.Choices) > 0 {
					fmt.Fprintf(&b, "            COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(f.Choices, " "))
				} else if f.IsFilePath {
					b.WriteString("            COMPREPLY=( $(compgen -f -- \"$cur\") )\n")
				}
				b.WriteString("            return 0\n            ;;\n")
			}
		}
		if hasPrevCases {
			b.WriteString("    esac\n\n")
		}

		b.WriteString(`    if [[ "$cword" -eq 1 && "$cur" != -* ]]; then
        COMPREPLY=( $(compgen -W "completion" -- "$cur") )
        return 0
    fi
    if [[ "${words[1]}" == "completion" && "$cword" -eq 2 ]]; then
        COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "$cur") )
        return 0
    fi

`)

		var flags []string
		for _, f := range cmd.Flags {
			flags = append(flags, "-"+f.Name, "--"+f.Name)
		}
		flags = append(flags, "-h", "--help")

		b.WriteString("    if [[ \"$cur\" == -* ]]; then\n")
		fmt.Fprintf(&b, "        COMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(flags, " "))
		b.WriteString("        return 0\n    fi\n")
	}

	fmt.Fprintf(&b, "}\n\ncomplete -o default -F %s %s\n", funcName, cmd.Name)
	_, err := io.WriteString(w, b.String())
	return err
}

func sanitizeFuncName(name string) string {
	r := strings.NewReplacer("-", "_", ".", "_", "/", "_", ":", "_")
	return r.Replace(name)
}
