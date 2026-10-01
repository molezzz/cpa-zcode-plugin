//go:build !darwin && !linux

package main

// runtimeOSVersion reports nothing on platforms the plugin does not target:
// the OS version header is omitted rather than guessed, matching the official
// builder's own handling of an unresolvable value.
func runtimeOSVersion() string { return "" }
