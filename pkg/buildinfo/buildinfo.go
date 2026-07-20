// Package buildinfo reports the binary version injected by release builds.
package buildinfo

import "runtime/debug"

// Version is set with -ldflags "-X .../pkg/buildinfo.Version=<version>".
var Version = ""

func String() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				if len(s.Value) > 12 {
					s.Value = s.Value[:12]
				}
				return "dev (" + s.Value + ")"
			}
		}
	}
	return "dev"
}
