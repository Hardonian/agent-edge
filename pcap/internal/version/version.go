package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current release version.
	Version = "1.0.0"
	// Commit is the git commit hash set at build time.
	Commit = "dev"
	// BuildDate is the ISO date when the binary was compiled.
	BuildDate = "2026-09-04"
)

// Info returns formatted version information.
func Info() string {
	return fmt.Sprintf("AgentPCAP v%s (commit: %s, built: %s, runtime: %s)", Version, Commit, BuildDate, runtime.Version())
}
