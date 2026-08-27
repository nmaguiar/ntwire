package clientopts

import "flag"

// FlagSet wraps a *flag.FlagSet built from the registry, with typed
// accessors so callers don't need to keep their own *string/*bool handles.
type FlagSet struct {
	*flag.FlagSet
	vals map[string]any // *string | *bool | *MultiValue
}

// NewFlagSet builds a flag.FlagSet for command from every Option the
// registry defines on it, using d to resolve config-layered defaults. The
// returned FlagSet has flag.ExitOnError semantics, matching every FlagSet
// cmd/ntwire has always used.
func NewFlagSet(command string, d Defaults) *FlagSet {
	f := &FlagSet{
		FlagSet: flag.NewFlagSet(command, flag.ExitOnError),
		vals:    map[string]any{},
	}
	for _, o := range For(command) {
		usage := Usage(o, command)
		def := ""
		if o.Default != nil {
			def = o.Default(d)
		}
		switch o.Kind {
		case KindString:
			f.vals[o.Name] = f.String(o.Name, def, usage)
		case KindBool:
			f.vals[o.Name] = f.Bool(o.Name, def == "true", usage)
		case KindKeyValue:
			m := &MultiValue{}
			f.Var(m, o.Name, usage)
			f.vals[o.Name] = m
		}
	}
	return f
}

// Str returns the current value of a KindString option registered on this
// FlagSet. It panics if name was not registered -- a programmer error, the
// same class of bug as indexing past a slice's length.
func (f *FlagSet) Str(name string) string {
	return *f.vals[name].(*string)
}

// BoolVal returns the current value of a KindBool option registered on this
// FlagSet. Named BoolVal, not Bool, so it does not shadow the embedded
// flag.FlagSet.Bool(name, value, usage) constructor method.
func (f *FlagSet) BoolVal(name string) bool {
	return *f.vals[name].(*bool)
}

// KeyValues returns the accumulated values of a KindKeyValue option
// registered on this FlagSet.
func (f *FlagSet) KeyValues(name string) []string {
	return []string(*f.vals[name].(*MultiValue))
}

// WasSet reports whether name appeared explicitly on the command line. It is
// useful when a persisted default must yield to an explicit, incompatible
// choice such as -i and --sso.
func (f *FlagSet) WasSet(name string) bool {
	set := false
	f.Visit(func(flag *flag.Flag) {
		if flag.Name == name {
			set = true
		}
	})
	return set
}

// Has reports whether name was registered on this FlagSet, without
// panicking. cmd/ntwire never needs this -- its option names are compile-time
// constants, so a mismatch there is a programmer error best caught by Str/
// BoolVal panicking immediately. A caller resolving names dynamically (a GUI
// driven by /api/schema, say) should check this first. Named Has, not
// Lookup, so it does not shadow the embedded flag.FlagSet.Lookup(name)
// *flag.Flag method, whose different return type would otherwise be hidden
// silently rather than causing a compile error.
func (f *FlagSet) Has(name string) bool {
	_, ok := f.vals[name]
	return ok
}
