//go:build linux

package main

import (
	"strings"
	"syscall"
)

// runtimeOSVersion returns the running kernel release (uname), the value the
// official client's os.version() reports on this platform. An empty return
// means the header is omitted rather than guessed.
func runtimeOSVersion() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return ""
	}
	release := make([]byte, 0, len(uts.Release))
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}
	return strings.TrimSpace(string(release))
}
