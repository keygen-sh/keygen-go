# Keygen Go SDK

Package [`keygen`](https://pkg.go.dev/github.com/keygen-sh/keygen-go) allows Go programs
to license and remotely update themselves using the keygen.sh service.

## License activation example

```go
import "github.com/keygen-sh/keygen-go"

keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
keygen.Product = os.Getenv("KEYGEN_PRODUCT")
keygen.Token = os.Getenv("KEYGEN_TOKEN")

func activate() error {
  fingerprint := uuid.New().String()

  // Validate the license for the current fingerprint
  license, err := keygen.Validate(fingerprint)
  switch {
  case err == ErrLicenseNotActivated:
    // Activate the current fingerprint
    machine, err := license.Activate(fingerprint)
    switch {
    case err != ErrMachineLimitExceeded:
      fmt.Println("Machine limit has been exceeded!")

      return err
    case err != nil:
      fmt.Println("Machine activaiton failed!")

      return err
    }
  }
  case err == ErrLicenseInvalid:
    fmt.Println("License is not valid!")

    return err
  case err == ErrLicenseExpired:
    fmt.Println("License is expired!")

    return err
  case err != nil:
    fmt.Println("License is invalid!")

    return err
}
```

## Automatic upgrade example

```go
import "github.com/keygen-sh/keygen-go"

keygen.Account = os.Getenv("KEYGEN_ACCOUNT")
keygen.Product = os.Getenv("KEYGEN_PRODUCT")
keygen.Token = os.Getenv("KEYGEN_TOKEN")

func upgrade() error {
  // Check for upgrade
  release, err := keygen.Upgrade("1.0.0")
  switch {
  case err == ErrUpgradeNotAvailable:
     fmt.Println("No upgrade available, already at the latest version!")

     return nil
  case err != nil:
    fmt.Println("Upgrade check failed!")

    return err
  }

  // Download the upgrade and apply it
  err = release.Install()
  if err != nil {
      return err
  }
}
```
