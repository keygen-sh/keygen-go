//go:build !windows
// +build !windows

package keygen

var (
	// Ext is the release artifact filename extension used when installing
	// upgrades. By default, binaries do not have an extension.
	Ext = ""
)
