//go:build !windows
// +build !windows

package keygen

var (
	// Filetype is the release filetype used when checking for upgrades.
	Filetype = "bin"
)
