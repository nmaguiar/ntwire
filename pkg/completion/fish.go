package completion

import (
	"fmt"
	"io"
	"strings"
)

// Fish generates a fish completion script for cmd.
func Fish(cmd Command, w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# fish completion for %s\n\n", cmd.Name)
	fmt.Fprintf(&b, "complete -c %s -f\n\n", cmd.Name)

	if len(cmd.Subcommands) > 0 {
		for _, sc := range cmd.Subcommands {
			desc := escapeFishDesc(sc.Summary)
			fmt.Fprintf(&b, "complete -c %s -n \"__fish_use_subcommand\" -a \"%s\" -d \"%s\"\n", cmd.Name, sc.Name, desc)
		}
		b.WriteString("\n")

		for _, f := range cmd.Flags {
			b.WriteString(fishFlagSpec(cmd.Name, "__fish_use_subcommand", f))
		}
		b.WriteString(fmt.Sprintf("complete -c %s -n \"__fish_use_subcommand\" -l help -s h -d \"show help\"\n\n", cmd.Name))

		for _, sc := range cmd.Subcommands {
			condition := fmt.Sprintf("__fish_seen_subcommand_from %s", sc.Name)
			for _, f := range sc.Flags {
				b.WriteString(fishFlagSpec(cmd.Name, condition, f))
			}
			b.WriteString(fmt.Sprintf("complete -c %s -n \"%s\" -l help -s h -d \"show help\"\n", cmd.Name, condition))

			if len(sc.ArgChoices) > 0 {
				fmt.Fprintf(&b, "complete -c %s -n \"%s\" -a \"%s\"\n", cmd.Name, condition, strings.Join(sc.ArgChoices, " "))
			}
			b.WriteString("\n")
		}
	} else {
		for _, f := range cmd.Flags {
			b.WriteString(fishFlagSpec(cmd.Name, "", f))
		}
		b.WriteString(fmt.Sprintf("complete -c %s -l help -s h -d \"show help\"\n", cmd.Name))
		fmt.Fprintf(&b, "complete -c %s -n \"__fish_is_first_token\" -a \"completion\" -d \"generate shell completion script\"\n", cmd.Name)
		fmt.Fprintf(&b, "complete -c %s -n \"__fish_seen_subcommand_from completion\" -a \"%s\"\n", cmd.Name, strings.Join(SupportedShells, " "))
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func fishFlagSpec(cmdName, condition string, f Flag) string {
	desc := escapeFishDesc(f.Usage)
	if desc == "" {
		desc = f.Name
	}
	var condPart string
	if condition != "" {
		condPart = fmt.Sprintf("-n \"%s\" ", condition)
	}

	var opts string
	if f.TakesValue {
		if len(f.Choices) > 0 {
			opts = fmt.Sprintf(" -r -f -a \"%s\"", strings.Join(f.Choices, " "))
		} else if f.IsFilePath {
			opts = " -r -F"
		} else {
			opts = " -r"
		}
	}

	return fmt.Sprintf("complete -c %s %s-l %s -o %s -d \"%s\"%s\n", cmdName, condPart, f.Name, f.Name, desc, opts)
}

func escapeFishDesc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
