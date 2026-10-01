//go:build darwin

package main

import "syscall"

// runtimeOSVersion returns the macOS product version (kern.osproductversion),
// the value the official client's os.version() reports on this platform. An
// empty return means the header is omitted rather than guessed.
func runtimeOSVersion() string {
	value, err := syscall.Sysctl("kern.osproductversion")
	if err != nil {
		return ""
	}
	return value
}
