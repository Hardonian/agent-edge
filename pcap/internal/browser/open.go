package browser

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Open launches the system default browser to the given URL.
func Open(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, freebsd, etc.
		cmd = exec.Command("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not open browser automatically: %w", err)
	}
	return nil
}
