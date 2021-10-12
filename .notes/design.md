# Keygen Dist

Will consist of 2 packages, written in Go:

- keygen/sdk
- keygen/cli

The SDK could export a C API to be used in other languages: https://golang.org/doc/go1.5#link

Use `equinox` as inspiration for the SDK and CLI: https://equinox.io/docs#release-tool

Create homebrew tap: https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap

CI for Travis CI: https://github.com/equinox-io/continuous-deployment-travis

CI for GitHub Actions: https://github.com/equinox-io/release

## SDK

Don't need to verify offline, because the entire SDK requires connectivity. Verifying offline
is simple without using the SDK.

Set user agent!

Give credit? https://github.com/equinox-io/equinox

v2: signature verification?

### Configuration

```go
keygen.Account = accountId
keygen.Product = productId
keygen.Token = token // Assert that this is a license token?
keygen.Backend = Backend{} // For mocking in tests

interface Client {
  Validate({ Key?, Fingerprint }): (License, error)
  Upgrade({ Version, Platform, Channel, Filetype, Constraint }): (Upgrade, error)
}

interface License {
  Name string
  Key string
  Expiry time.RFC3339Nano // time.Parse(time.RFC3339Nano, "2013-06-05T14:10:43.678Z")
  LastValidated time.RFC3339Nano
  Created time.RFC3339Nano
  Updated time.RFC3339Nano
  Metadata interface{}

  Activate({ Fingerprint }) (Machine, error)
  Deactivate({ Fingerprint }) error
  Machines() (Machines[], error)
  Entitlements() (Entitlements[], error)
}

interface Machine {
  Name string
  Fingerprint string
  Metadata interface{}

  Deactivate() error
  Monitor(chan error)
}

interface Upgrade {
  Version string
  Name string
  Created time.RFC3339Nano
  Updated time.RFC3339Nano
  Metadata interface{}

  Install() chan error
}
```

### Check for upgrades

Upgrade by version. Follow artifact's release link and expose its attributes.

```go
upgrade, err := keygen.Upgrade({ Version: currentVersion })
switch {
case err == keygen.UpgradeNotAvailableError:
  fmt.Println("No upgrade available, already at the latest version!")
case err != nil:
  fmt.Println("Upgrade check failed:", err)
}
```

Expose download progress?

### Install upgrade

Verify SHA-256 checksum.

```go
err = upgrade.Install()
if err != nil {
  fmt.Println("Upgrade install failed:", err)
  return err
}

fmt.Printf("Upgraded to new version: %s!\n", upgrade.Version)
```

Expose upgrade progress?

### Validate license

Unless `key` is provided, use `keygen.Token` to request current bearer and validate license by ID.

```go
license, err := keygen.Validate({ Fingerprint: deviceFingerprint })
switch {
case err == keygen.NotActivatedError:
  fmt.Println("Fingerprint has not been activated!")
case err == keygen.LicenseExpiredError:
  fmt.Println("Your license is expired!")
case err == keygen.FingerprintRequiredError:
  fmt.Println("Fingerprint is required but is missing!")
case err != nil:
  fmt.Println("License validation failed:", err)
}
```

### Activate machine

```go
machine, err := license.Activate({ Fingerprint: deviceFingerprint })
switch {
case err == keygen.MachineAlreadyActivatedError:
  fmt.Println("Your machine is already activated!")
case err != nil:
  fmt.Println("Activation failed:", err)
}
```

### Deactivate machine

```go
err = machine.Deactivate() // or license.Deactivate({ Fingerprint: deviceFingerprint })
if err != nil {
  fmt.Println("Deactivation failed:", err)
}
```

### Monitor machine heartbeats

```go
errs := machine.Monitor()
select {
  case err := <-errs:
    switch {
    case err == keygen.HeartbeatPingFailedError:
      fmt.Println("Heartbeat ping failed to reach the server!")
    case err == keygen.MachineNotFoundError:
      fmt.Println("Monitor was started for a machine that no longer exists!")

      panic()
    case err != nil:
      fmt.Println("Heartbeat error:", err)
    }
}
```

## CLI

### Plugin system

Add before/after hooks to support additional signing for Windows/macOS.

Ref: https://github.com/equinox-io/equinox/issues/13

### Generate signing keys

Should error if keys already exist.

```bash
$ keygen genkey --algorithm ed25519

Private key file              /Users/zeke/keygen.key
Public key file               /Users/zeke/keygen.pub
```

### Release from filesystem

```bash
$ keygen releases new ./dist/app-1.0.0.dmg \
    --signing-key=/Users/zeke/keygen.key \
    --account "..." \
    --token "..." \
    --constraints "APP_V1,APP_DL,APP_UP"
    --platform "darwin_amd64" \
    --version "1.0.0" \
    --channel "stable"
```

### Release from GitHub

Pull releases from GitHub Releases and upload to Dist.

Or use GH Actions for this?

```bash
$ keygen releases new github.com/acme/rocket \
    --config ./keygen.yaml \
    --version "1.0.0"
```

### Generate license

Batch create licenses? Obey rate limiter.

## Notes

```ts
enum SigningAlgorithm {
  Ed25519 = 'ED25519_SIGN',
  RSAPSS = 'RSA_2048_PKCS1_PSS_SIGN',
}

enum ValidationCode {
  Valid = 'VALID',
  NotActivated = 'NOT_ACTIVATED',
  Expired = 'EXPIRED',
  Suspended = 'SUSPENDED',
}

interface Validation {
  valid: boolean
  code: ValidationCode
}

interface License {
  id: string
  name: string | null
  key: string
  algorithm: SigningAlgorithm | null
  expiry: string | null
  maxActivations: number
  activations: number
  metadata: object
}

interface Activation {
  id: string
  name: string
  fingerprint: string
  metadata: object
}

class Client {
  private account: string
  private product: string
  private token: string

  license: License

  constructor(account: string, product: string, token: string)

  // Validate the license
  isValid(): boolean

  // Validate license scoped to current machine
  isActivated(): boolean

  // Check if activations < maxActivations
  hasActivation(): boolean

  // Check if license is expired
  isExpired(): boolean

  // Check if license is suspended
  isSuspended(): boolean

  // Cryptographically verify license key (raise if not signed)
  isGenuine(): boolean

  // Check if an upgrade is available
  isUpgradeAvailable(): boolean

  // Validate the license
  validate(): Validation

  // Activate the current machine
  activate(): Activation

  // Deactivate the current machine
  deactivate(): void

  // Upgrade the application (Sparkle?)
  upgrade(): void
}
```
