package completion

import (
	"fmt"
	"io"
	"strings"
)

// PowerShell generates a PowerShell argument completer script for cmd.
func PowerShell(cmd Command, w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# powershell completion for %s\n\n", cmd.Name)
	fmt.Fprintf(&b, "Register-ArgumentCompleter -Native -CommandName '%s' -ScriptBlock {\n", cmd.Name)
	b.WriteString(`    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        $commandElements |
        Select-Object -ExpandProperty Value |
        Where-Object { $_ -and $_ -notlike '-*' }
    )

    $subcommand = if ($command.Count -gt 1) { $command[1] } else { '' }
    $prev = if ($commandElements.Count -gt 1) { $commandElements[-2].Value } else { '' }

`)

	if len(cmd.Subcommands) > 0 {
		b.WriteString(`    if ($subcommand -eq '') {
        if ($wordToComplete -like '-*') {
            $flags = @(
`)
		for _, f := range cmd.Flags {
			desc := escapePsString(f.Usage)
			fmt.Fprintf(&b, "                [PSCustomObject]@{ Name = '-%s'; ToolTip = '%s' }\n", f.Name, desc)
			fmt.Fprintf(&b, "                [PSCustomObject]@{ Name = '--%s'; ToolTip = '%s' }\n", f.Name, desc)
		}
		b.WriteString(`                [PSCustomObject]@{ Name = '-h'; ToolTip = 'show help' }
                [PSCustomObject]@{ Name = '--help'; ToolTip = 'show help' }
            )
            $flags | Where-Object { $_.Name -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterName', $_.ToolTip)
            }
            return
        }

        $subcommands = @(
`)
		for _, sc := range cmd.Subcommands {
			desc := escapePsString(sc.Summary)
			fmt.Fprintf(&b, "            [PSCustomObject]@{ Name = '%s'; ToolTip = '%s' }\n", sc.Name, desc)
		}
		b.WriteString(`        )
        $subcommands | Where-Object { $_.Name -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'Command', $_.ToolTip)
        }
        return
    }

    switch ($subcommand) {
`)
		for _, sc := range cmd.Subcommands {
			fmt.Fprintf(&b, "        '%s' {\n", sc.Name)
			// Handle file / choices args for flags in this subcommand
			for _, f := range sc.Flags {
				if len(f.Choices) > 0 {
					var psChoices []string
					for _, c := range f.Choices {
						psChoices = append(psChoices, fmt.Sprintf("'%s'", escapePsString(c)))
					}
					fmt.Fprintf(&b, `            if ($prev -eq '-%s' -or $prev -eq '--%s') {
                @(%s) | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
                return
            }
`, f.Name, f.Name, strings.Join(psChoices, ", "))
				} else if f.IsFilePath {
					fmt.Fprintf(&b, `            if ($prev -eq '-%s' -or $prev -eq '--%s') {
                Get-ChildItem -Path "$wordToComplete*" -ErrorAction SilentlyContinue | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_.FullName, $_.Name, 'ProviderItem', $_.FullName)
                }
                return
            }
`, f.Name, f.Name)
				}
			}

			b.WriteString(`            if ($wordToComplete -like '-*') {
                $flags = @(
`)
			for _, f := range sc.Flags {
				desc := escapePsString(f.Usage)
				fmt.Fprintf(&b, "                    [PSCustomObject]@{ Name = '-%s'; ToolTip = '%s' }\n", f.Name, desc)
				fmt.Fprintf(&b, "                    [PSCustomObject]@{ Name = '--%s'; ToolTip = '%s' }\n", f.Name, desc)
			}
			b.WriteString(`                    [PSCustomObject]@{ Name = '-h'; ToolTip = 'show help' }
                    [PSCustomObject]@{ Name = '--help'; ToolTip = 'show help' }
                )
                $flags | Where-Object { $_.Name -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterName', $_.ToolTip)
                }
                return
            }
`)
			if len(sc.ArgChoices) > 0 {
				var psChoices []string
				for _, c := range sc.ArgChoices {
					psChoices = append(psChoices, fmt.Sprintf("'%s'", escapePsString(c)))
				}
				fmt.Fprintf(&b, `            @(%s) | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
            return
`, strings.Join(psChoices, ", "))
			}
			b.WriteString("        }\n")
		}
		b.WriteString("    }\n")
	} else {
		// Single-command binary
		for _, f := range cmd.Flags {
			if len(f.Choices) > 0 {
				var psChoices []string
				for _, c := range f.Choices {
					psChoices = append(psChoices, fmt.Sprintf("'%s'", escapePsString(c)))
				}
				fmt.Fprintf(&b, `    if ($prev -eq '-%s' -or $prev -eq '--%s') {
        @(%s) | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }
`, f.Name, f.Name, strings.Join(psChoices, ", "))
			} else if f.IsFilePath {
				fmt.Fprintf(&b, `    if ($prev -eq '-%s' -or $prev -eq '--%s') {
        Get-ChildItem -Path "$wordToComplete*" -ErrorAction SilentlyContinue | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_.FullName, $_.Name, 'ProviderItem', $_.FullName)
        }
        return
    }
`, f.Name, f.Name)
			}
		}

		b.WriteString(`    if ($command.Count -eq 1 -and $wordToComplete -notlike '-*') {
        @([PSCustomObject]@{ Name = 'completion'; ToolTip = 'generate shell completion script' }) |
            Where-Object { $_.Name -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'Command', $_.ToolTip)
            }
        return
    }
    if ($command.Count -gt 1 -and $command[1] -eq 'completion') {
        @('bash', 'zsh', 'fish', 'powershell') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }

    if ($wordToComplete -like '-*') {
        $flags = @(
`)
		for _, f := range cmd.Flags {
			desc := escapePsString(f.Usage)
			fmt.Fprintf(&b, "            [PSCustomObject]@{ Name = '-%s'; ToolTip = '%s' }\n", f.Name, desc)
			fmt.Fprintf(&b, "            [PSCustomObject]@{ Name = '--%s'; ToolTip = '%s' }\n", f.Name, desc)
		}
		b.WriteString(`            [PSCustomObject]@{ Name = '-h'; ToolTip = 'show help' }
            [PSCustomObject]@{ Name = '--help'; ToolTip = 'show help' }
        )
        $flags | Where-Object { $_.Name -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterName', $_.ToolTip)
        }
        return
    }
`)
	}

	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func escapePsString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
