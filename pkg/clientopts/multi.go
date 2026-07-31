package clientopts

import "strings"

// MultiValue is a flag.Value that accumulates repeated occurrences of a
// flag, such as "-port name=1234 -port other=5678".
type MultiValue []string

func (m *MultiValue) String() string     { return strings.Join(*m, ",") }
func (m *MultiValue) Set(v string) error { *m = append(*m, v); return nil }
