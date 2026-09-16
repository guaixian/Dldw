// Package version carries build information set via -ldflags.
package version

var (
	Version = "1.0.0"
	Commit  = "dev"
	Date    = "unknown"
)

// String returns a printable version line.
func String() string { return "dldw " + Version + " (" + Commit + ", " + Date + ")" }
