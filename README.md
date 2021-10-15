# Keygen Go SDK [![godoc reference](https://godoc.org/github.com/keygen-sh/keygen-go?status.png)](https://godoc.org/github.com/keygen-sh/keygen-go)

Package [`keygen`](https://pkg.go.dev/github.com/keygen-sh/keygen-go) allows Go programs to
license and remotely update themselves using the [keygen.sh](https://keygen.sh) service.

## Usage

### `keygen.Validate(fingerprint)`

To validate a license, configure `keygen.Account` and `keygen.Product` with your Keygen account
details. Then prompt the user for their license token and set `keygen.Token`.

The `Validate` method accepts zero or more fingerprints, which can be used to scope a license
validation to a particular fingerprint. It will return a `License` object as well as any
validation errors that occur. The `License` object can be used to perform additional actions,
such as `license.Activate(fingerprint)`.

```go
license, err := keygen.Validate(fingerprint)
switch {
case err == keygen.ErrLicenseNotActivated:
  fmt.Println("License is not activated!")

  return
case err == keygen.ErrLicenseExpired:
  fmt.Println("License is expired!")

  return
case err != nil:
  fmt.Println("License is invalid!")

  return
}

fmt.Println("License is valid!")
```

### `keygen.Upgrade(currentVersion)`

Check for an upgrade. When an upgrade is available, a `Release` will be returned which will
allow the update to be installed, replacing the currently running binary. When an upgrade
is not available, an `ErrUpgradeNotAvailable` error will be returned indicating the current
version is up-to-date.

```go
release, err := keygen.Upgrade(currentVersion)
switch {
case err == keygen.ErrUpgradeNotAvailable:
  fmt.Println("No upgrade available, already at the latest version!")

  return
case err != nil:
  fmt.Println("Upgrade check failed!")

  return
}

if err := release.Install(); err != nil {
  fmt.Println("Upgrade install failed!")

  return
}

fmt.Println("Upgrade complete! Please restart.")
```

### `keygen.Genuine(licenseKey, schemeCode)`

Cryptographically verify and decode a signed license key. This is useful for checking if a license
key is genuine in offline or air-gapped environments. Returns the key's decoded dataset and any
errors that occurred during cryptographic verification, e.g. `ErrLicenseNotGenuine`.

Requires that `keygen.PublicKey` is set.

```go
dataset, err := keygen.Genuine(licenseKey, keygen.SchemeCodeEd25519)
switch {
case err == keygen.ErrLicenseNotGenuine:
  fmt.Println("License key is not genuine!")

  return
case err != nil:
  fmt.Println("Genuine check failed!")

  return
}

fmt.Printf("Decoded dataset: %s\n", dataset)
```

---

## Examples

### License activation example

```go
package main

import (
  "fmt"

  "github.com/google/uuid"
  "github.com/keygen-sh/keygen-go"
)

func main() {
  keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
  keygen.Product = os.Getenv("KEYGEN_PRODUCT")
  keygen.Token = os.Getenv("KEYGEN_TOKEN")

  // The current device's fingerprint (could be e.g. MAC, mobo ID, GUID, etc.)
  fingerprint := uuid.New().String()

  // Validate the license for the current fingerprint
  license, err := keygen.Validate(fingerprint)
  switch {
  case err == keygen.ErrLicenseNotActivated:
    // Activate the current fingerprint
    machine, err := license.Activate(fingerprint)
    switch {
    case err == keygen.ErrMachineLimitExceeded:
      fmt.Println("Machine limit has been exceeded!")

      return
    case err != nil:
      fmt.Println("Machine activation failed!")

      return
    }
  case err == keygen.ErrLicenseExpired:
    fmt.Println("License is expired!")

    return
  case err != nil:
    fmt.Println("License is invalid!")

    return
  }

  fmt.Println("License is activated!")
}
```

### Automatic upgrade example

```go
package main

import (
  "fmt"
  "os"

  "github.com/keygen-sh/keygen-go"
)

const (
  // The current version of the program
  currentVersion = "1.0.0"
)

func main() {
  keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
  keygen.Product = os.Getenv("KEYGEN_PRODUCT")
  keygen.Token = os.Getenv("KEYGEN_TOKEN")

  fmt.Printf("Current version: %s\n", currentVersion)
  fmt.Println("Checking for upgrades...")

  // Check for upgrade
  release, err := keygen.Upgrade(currentVersion)
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
    fmt.Println("Upgrade install failed!")

    return
  }

  fmt.Printf("Upgrade complete! Now on version: %s\n", release.Version)
  fmt.Println("Restart to finish installation...")
}
```

### Machine heartbeats example

```go
package main

import (
  "fmt"
  "os"
  "os/signal"

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
    switch {
    case err != nil:
      fmt.Println("Machine activation failed!")

      panic(err)
    }

    fmt.Println("Machine was activated!")

    // Handle SIGINT and SIGTERM events and gracefully deactivate the machine
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
    errs := machine.Monitor()

    go func() {
      for {
        select {
        case err := <-errs:
          // We want to kill the current process if our heartbeat ping fails
          panic(err)
        default:
          continue
        }
      }
    }()
  case err != nil:
    fmt.Println("License is invalid!")

    return
  }

  fmt.Println("License is activated!")

  <-done
}

```
