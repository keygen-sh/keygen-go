# Keygen Go SDK [![godoc reference](https://godoc.org/github.com/keygen-sh/keygen-go?status.png)](https://godoc.org/github.com/keygen-sh/keygen-go)

Package [`keygen`](https://pkg.go.dev/github.com/keygen-sh/keygen-go) allows Go programs to
license and remotely update themselves using the [keygen.sh](https://keygen.sh) service.

## Config

### `keygen.Account`

`Account` is your Keygen account ID used globally in the binding. All requests will be made
to this account. This should be hard-coded into your app.

```go
keygen.Account = "1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"
```

### `keygen.Product`

`Product` is your Keygen product ID used globally in the binding. All license validations and
upgrade requests will be scoped to this product. This should be hard-coded into your app.

```go
keygen.Product = "1f086ec9-a943-46ea-9da4-e62c2180c2f4"
```

### `keygen.LicenseKey`

`LicenseKey` a license key belonging to the end-user (licensee). This will be used for license
validations, activations, deactivations and upgrade requests. You will need to prompt the
end-user for this value.

You will need to set the license policy's authentication strategy to `LICENSE` or `MIXED`.

Setting `LicenseKey` will take precedence over `Token`.

```go
keygen.LicenseKey = "C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3"
```

### `keygen.Token`

`Token` is an activation token belonging to the licensee. This will be used for license validations,
activations, deactivations and upgrade requests. You will need to prompt the end-user for this.

You will need to set the license policy's authentication strategy to `TOKEN` or `MIXED`.

```go
keygen.Token = "activ-d66e044ddd7dcc4169ca9492888435d3v3"
```

### `keygen.PublicKey`

`PublicKey` is your Keygen account's hex-encoded Ed25519 public key, used for verifying signed license keys
and API response signatures. When set, API response signatures will automatically be verified. You may
leave it blank to skip verifying response signatures. This should be hard-coded into your app.

```go
keygen.PublicKey = "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788"
```

### `keygen.Logger`

`Logger` is a leveled logger implementation used for printing debug, informational, warning, and
error messages. The default log level is `LogLevelError`. You may provide your own logger which
implements `LoggerInterface`.

```go
keygen.Logger = &CustomLogger{Level: LogLevelDebug}
```

## Usage

The following top-level functions are available. We recommend starting here.

### `keygen.Validate(fingerprints...)`

To validate a license, configure `keygen.Account` and `keygen.Product` with your Keygen account
details. Then prompt the end-user for their license key or token and set `keygen.LicenseKey`
or `keygen.Token`, respectively.

The `Validate` method accepts zero or more fingerprints, which can be used to scope a license
validation to a particular fingerprint. It will return a `License` object as well as any
validation errors that occur. The `License` object can be used to perform additional actions,
such as `license.Activate(fingerprint)`.

```go
license, err := keygen.Validate(fingerprint)
switch {
case err == keygen.ErrLicenseNotActivated:
  panic("License is not activated!")
case err == keygen.ErrLicenseExpired:
  panic("License is expired!")
case err != nil:
  panic("License is invalid!")
}

fmt.Println("License is valid!")
```

### `keygen.Upgrade(version)`

Check for an upgrade. When an upgrade is available, a `Release` will be returned which will
allow the update to be installed, replacing the currently running binary. When an upgrade
is not available, an `ErrUpgradeNotAvailable` error will be returned indicating the current
version is up-to-date.

When a `PublicKey` is provided, the release's signature will be verified before installing.
The public MUST be a personal Ed25519ph public key. It MUST NOT be your Keygen account's
public key. You can read more about generating a personal keypair and about code signing
[here](https://keygen.sh/docs/cli/#code-signing).

```go
opts := keygen.UpgradeOptions{CurrentVersion: "1.0.0", Channel: "stable", PublicKey: "5ec69b78d4b5d4b624699cef5faf3347dc4b06bb807ed4a2c6740129f1db7159"}

// Check for an upgrade
release, err := keygen.Upgrade(opts)
switch {
case err == keygen.ErrUpgradeNotAvailable:
  fmt.Println("No upgrade available, already at the latest version!")

  return
case err != nil:
  fmt.Println("Upgrade check failed!")

  return
}

// Install the upgrade
if err := release.Install(); err != nil {
  panic("Upgrade install failed!")
}

fmt.Println("Upgrade complete! Please restart.")
```

To quickly generate a keypair, use [Keygen's CLI](https://github.com/keygen-sh/keygen-cli):

```bash
keygen genkey
```

## Examples

Below are various implementation examples, covering common licensing scenarios and use cases.

### License Activation

Validate the license for a particular device fingerprint, and activate when needed. We're
using `machineid` for fingerprinting, which is cross-platform, using the operating
system's native GUID.

```go
package main

import (
  "github.com/denisbrodbeck/machineid"
  "github.com/keygen-sh/keygen-go"
)

func main() {
  keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
  keygen.Product = os.Getenv("KEYGEN_PRODUCT")
  keygen.Token = os.Getenv("KEYGEN_TOKEN")

  fingerprint, err := machineid.ProtectedID(keygen.Account)
  if err != nil {
    panic(err)
  }

  // Validate the license for the current fingerprint
  license, err := keygen.Validate(fingerprint)
  switch {
  case err == keygen.ErrLicenseNotActivated:
    // Activate the current fingerprint
    machine, err := license.Activate(fingerprint)
    switch {
    case err == keygen.ErrMachineLimitExceeded:
      panic("Machine limit has been exceeded!")
    case err != nil:
      panic("Machine activation failed!")
    }
  case err == keygen.ErrLicenseExpired:
    panic("License is expired!")
  case err != nil:
    panic("License is invalid!")
  }

  fmt.Println("License is activated!")
}
```

### Automatic Upgrades

Check for an upgrade and automatically replace the current binary with the newest version.

```go
package main

import "github.com/keygen-sh/keygen-go"

// The current version of the program
const CurrentVersion = "1.0.0"

func main() {
  keygen.PublicKey = os.Getenv("KEYGEN_PUBLIC_KEY")
  keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
  keygen.Product = os.Getenv("KEYGEN_PRODUCT")
  keygen.Token = os.Getenv("KEYGEN_TOKEN")

  fmt.Printf("Current version: %s\n", CurrentVersion)
  fmt.Println("Checking for upgrades...")

  opts := keygen.UpgradeOptions{CurrentVersion: CurrentVersion, Channel: "stable", PublicKey: os.Getenv("COMPANY_PUBLIC_KEY")}

  // Check for upgrade
  release, err := keygen.Upgrade(opts)
  switch {
  case err == keygen.ErrUpgradeNotAvailable:
    fmt.Println("No upgrade available, already at the latest version!")

    return
  case err != nil:
    fmt.Println("Upgrade check failed!")

    return
  }

  // Download the upgrade and install it
  err = release.Install()
  if err != nil {
    panic("Upgrade install failed!")
  }

  fmt.Printf("Upgrade complete! Installed version: %s\n", release.Version)
  fmt.Println("Restart to finish installation...")
}
```

### Machine Heartbeats

Monitor a machine's heartbeat, and automatically deactivate machines in case of a crash
or an unresponsive node. We recommend using a random UUID fingerprint for activating
nodes in cloud-based scenarios, since nodes may share underlying hardware.

```go
package main

import (
  "github.com/google/uuid"
  "github.com/keygen-sh/keygen-go"
)

func main() {
  keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
  keygen.Product = os.Getenv("KEYGEN_PRODUCT")
  keygen.Token = os.Getenv("KEYGEN_TOKEN")

  // The current device's fingerprint (could be e.g. MAC, mobo ID, GUID, etc.)
  fingerprint := uuid.New().String()

  // Keep our example process alive
  done := make(chan bool, 1)

  // Validate the license for the current fingerprint
  license, err := keygen.Validate(fingerprint)
  switch {
  case err == keygen.ErrLicenseNotActivated:
    // Activate the current fingerprint
    machine, err := license.Activate(fingerprint)
    if err != nil {
      fmt.Println("Machine activation failed!")

      panic(err)
    }

    // Handle SIGINT and gracefully deactivate the machine
    sigs := make(chan os.Signal, 1)

    signal.Notify(sigs, os.Interrupt)

    go func() {
      for sig := range sigs {
        fmt.Printf("Caught %v, deactivating machine and gracefully exiting...\n", sig)

        if err := machine.Deactivate(); err != nil {
          fmt.Println("Machine deactivation failed!")

          panic(err)
        }

        fmt.Println("Machine was deactivated!")
        fmt.Println("Exiting...")

        done <- true
      }
    }()

    // Start a heartbeat monitor for the current machine
    if err := machine.Monitor(); err != nil {
      fmt.Println("Machine heartbeat monitor failed to start!")

      panic(err)
    }

    fmt.Println("Machine is activated and monitored!")
  case err != nil:
    fmt.Println("License is invalid!")

    panic(err)
  }

  fmt.Println("License is valid!")

  <-done
}
```

### Offline License Files

Cryptographically verify and decrypt an encrypted license file. This is useful for checking if a license
file is genuine in offline or air-gapped environments. Returns the license file's dataset and any
errors that occurred during verification and decryption, e.g. `ErrLicenseFileNotGenuine`.

When decrypting a license file, you MUST provide the license's key as the decryption key.

When initializing a `LicenseFile`, `Certificate` is required.

Requires that `keygen.PublicKey` is set.

```go
package main

import "github.com/keygen-sh/keygen-go"

func main() {
  keygen.PublicKey = os.Getenv("KEYGEN_PUBLIC_KEY")

  lic := &keygen.LicenseFile{Certificate: "-----BEGIN LICENSE FILE-----\n..."}
  err := lic.Verify()
  switch {
  case err == keygen.ErrLicenseFileNotGenuine:
    panic("License file is not genuine!")
  case err != nil:
    panic(err)
  }

  dataset, err := lic.Decrypt("key/...")
  if err != nil {
    panic(err)
  }

  fmt.Println("License file is genuine!")
  fmt.Printf("Decrypted dataset: %s\n", dataset)
}
```

### Offline License Keys

Cryptographically verify and decode a signed license key. This is useful for checking if a license
key is genuine in offline or air-gapped environments. Returns the key's decoded dataset and any
errors that occurred during cryptographic verification, e.g. `ErrLicenseKeyNotGenuine`.

When initializing a `License`, `Scheme` and `Key` are required.

Requires that `keygen.PublicKey` is set.

```go
package main

import "github.com/keygen-sh/keygen-go"

func main() {
  keygen.PublicKey = os.Getenv("KEYGEN_PUBLIC_KEY")

  license := &keygen.License{Scheme: keygen.SchemeCodeEd25519, Key: "key/..."}
  dataset, err := license.Verify()
  switch {
  case err == keygen.ErrLicenseKeyNotGenuine:
    panic("License key is not genuine!")
  case err != nil:
    panic(err)
  }

  fmt.Println("License is genuine!")
  fmt.Printf("Decoded dataset: %s\n", dataset)
}
```
