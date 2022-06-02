package keygen

type UpgradeOptions struct {
	// CurrentVersion is the current version of the program. This will be used by
	// Keygen to determine if an upgrade is available.
	CurrentVersion string

	// Constraint is a version constraint to use when checking for upgrades. For
	// example, to pin upgrades to v1, you would pass a "1.0" constraint.
	Constraint string

	// Channel is the release channel. One of: stable, rc, beta, alpha or dev.
	Channel string

	// PublicKey is your personal Ed25519ph public key, generated using Keygen's CLI
	// or using ssh-keygen. This will be used to verify the release's signature
	// before install. This MUST NOT be your Keygen account's public key.
	PublicKey string

	// Filename is the template string used when retrieving an artifact during
	// install. This should compile to a valid artifact identifier, e.g. a
	// filename for the current platform and arch.
	//
	// The default template is below:
	//
	//   {{.program}}_{{.platform}}_{{.arch}}{{if .ext}}.{{.ext}}{{end}}
	//
	// Available template variables:
	//
	//   program  // the name of the currently running program (i.e. basename of os.Args[0])
	//   ext      // the extension based on current platform (i.e. exe on Windows)
	//   platform // the current platform (i.e. GOOS)
	//   arch     // the current architecture (i.e. GOARCH)
	//   channel  // the release channel (e.g. stable)
	//   version  // the release version (e.g. 1.0.0-beta.3)
	//
	// If more control is needed, provide a string.
	Filename string
}

// Upgrade checks if an upgrade is available for the provided version. Returns a
// Release and any errors that occurred, e.g. ErrUpgradeNotAvailable.
func Upgrade(options UpgradeOptions) (*Release, error) {
	if options.PublicKey == PublicKey {
		panic("You MUST use a personal public key. This MUST NOT be your Keygen account's public key.")
	}

	if options.Filename == "" {
		options.Filename = `{{.program}}_{{.platform}}_{{.arch}}{{if .ext}}.{{.ext}}{{end}}`
	}

	if options.Channel == "" {
		options.Channel = "stable"
	}

	client := &Client{Account: Account, LicenseKey: LicenseKey, Token: Token, PublicKey: PublicKey, UserAgent: UserAgent}
	params := querystring{Constraint: options.Constraint, Channel: options.Channel}
	release := &Release{}

	if _, err := client.Get("releases/"+options.CurrentVersion+"/upgrade", params, release); err != nil {
		switch err.(type) {
		case *NotFoundError:
			return nil, ErrUpgradeNotAvailable
		default:
			return nil, err
		}
	}

	release.opts = options

	return release, nil
}
