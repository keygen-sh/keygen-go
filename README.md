# Keygen Go SDK [![godoc reference](https://godoc.org/github.com/keygen-sh/keygen-go?status.png)](https://godoc.org/github.com/keygen-sh/keygen-go)

Package [`keygen`](https://pkg.go.dev/github.com/keygen-sh/keygen-go) allows Go programs to
license and remotely update themselves using the [keygen.sh](https://keygen.sh) service.

## License activation example

```go
import "github.com/keygen-sh/keygen-go"

func activate() error {
  keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
  keygen.Product = os.Getenv("KEYGEN_PRODUCT")
  keygen.Token = os.Getenv("KEYGEN_TOKEN")

  // The current device's fingerprint (could be e.g. MAC, mobo ID, GUID, etc.)
  fingerprint := uuid.New().String()

  // Validate the license for the current fingerprint
  license, err := keygen.Validate(fingerprint)
  switch {
  case err == ErrLicenseNotActivated:
    // Activate the current fingerprint
    machine, err := license.Activate(fingerprint)
    switch {
    case err == ErrMachineLimitExceeded:
      fmt.Println("Machine limit has been exceeded!")

      return err
    case err != nil:
      fmt.Println("Machine activaiton failed!")

      return err
    }
  case err == ErrLicenseExpired:
    fmt.Println("License is expired!")

    return err
  case err != nil:
    fmt.Println("License is invalid!")

    return err
  }

  fmt.Println("License is activated!")
}
```

## Automatic upgrade example

```go
import "github.com/keygen-sh/keygen-go"

func upgrade() error {
  keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
  keygen.Product = os.Getenv("KEYGEN_PRODUCT")
  keygen.Token = os.Getenv("KEYGEN_TOKEN")

  // The current version of the program
  currentVersion := "1.0.0"

  // Check for upgrade
  release, err := keygen.Upgrade(currentVersion)
  switch {
  case err == ErrUpgradeNotAvailable:
    fmt.Println("No upgrade available, already at the latest version!")

    return nil
  case err != nil:
    fmt.Println("Upgrade check failed!")

    return err
  }

  // Download the upgrade and install it
  err = release.Install()
  if err != nil {
    return err
  }

  fmt.Println("Upgrade complete! Please restart.")
}
```
