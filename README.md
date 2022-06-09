# Keygen Go SDK [![godoc reference](https://godoc.org/github.com/keygen-sh/keygen-go/v2?status.png)](https://godoc.org/github.com/keygen-sh/keygen-go/v2)

Package [`keygen`](https://pkg.go.dev/github.com/keygen-sh/keygen-go/v2) allows Go programs to
license and remotely update themselves using the [keygen.sh](https://keygen.sh) service.

## Config

### keygen.Account

`Account` is your Keygen account ID used globally in the binding. All requests will be made
to this account. This should be hard-coded into your app.

```go
keygen.Account = "1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"
```

### keygen.Product

`Product` is your Keygen product ID used globally in the binding. All license validations and
upgrade requests will be scoped to this product. This should be hard-coded into your app.

```go
keygen.Product = "1f086ec9-a943-46ea-9da4-e62c2180c2f4"
```

### keygen.LicenseKey

`LicenseKey` a license key belonging to the end-user (licensee). This will be used for license
validations, activations, deactivations and upgrade requests. You will need to prompt the
end-user for this value.

You will need to set the license policy's authentication strategy to `LICENSE` or `MIXED`.

Setting `LicenseKey` will take precedence over `Token`.

```go
keygen.LicenseKey = "C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3"
```

### keygen.Token

`Token` is an activation token belonging to the licensee. This will be used for license validations,
activations, deactivations and upgrade requests. You will need to prompt the end-user for this.

You will need to set the license policy's authentication strategy to `TOKEN` or `MIXED`.

```go
keygen.Token = "activ-d66e044ddd7dcc4169ca9492888435d3v3"
```

### keygen.PublicKey

`PublicKey` is your Keygen account's hex-encoded Ed25519 public key, used for verifying signed license keys
and API response signatures. When set, API response signatures will automatically be verified. You may
leave it blank to skip verifying response signatures. This should be hard-coded into your app.

```go
keygen.PublicKey = "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788"
```

### keygen.Logger

`Logger` is a leveled logger implementation used for printing debug, informational, warning, and
error messages. The default log level is `LogLevelError`. You may provide your own logger which
implements `LeveledLogger`.

```go
keygen.Logger = &CustomLogger{Level: keygen.LogLevelDebug}
```

## Usage

The following top-level functions are available. We recommend starting here.

### keygen.Validate(fingerprints ...string)

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
  panic("license is not activated!")
case err == keygen.ErrLicenseExpired:
  panic("license is expired!")
case err != nil:
  panic("license is invalid!")
}

fmt.Println("License is valid!")
```

### keygen.Upgrade(options keygen.UpgradeOptions)

Check for an upgrade. When an upgrade is available, a `Release` will be returned which will
allow the update to be installed, replacing the currently running binary. When an upgrade
is not available, an `ErrUpgradeNotAvailable` error will be returned indicating the current
version is up-to-date.

When a `PublicKey` is provided, and the release has a `Signature`, the signature will be
cryptographically verified using Ed25519ph before installing. The `PublicKey` MUST be a
personal Ed25519ph public key. It MUST NOT be your Keygen account's public key (method
will panic if public keys match).

You can read more about generating a personal keypair and about code signing [here](https://keygen.sh/docs/cli/#code-signing).

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
  panic("upgrade install failed!")
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
using [`machineid`](https://github.com/denisbrodbeck/machineid) for fingerprinting, which
is cross-platform, using the operating system's native GUID.

```go
package main

import (
  "github.com/denisbrodbeck/machineid"
  "github.com/keygen-sh/keygen-go/v2"
)

func main() {
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "key/..."

  fingerprint, err := machineid.ProtectedID(keygen.Product)
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
      panic("machine limit has been exceeded!")
    case err != nil:
      panic("machine activation failed!")
    }
  case err == keygen.ErrLicenseExpired:
    panic("license is expired!")
  case err != nil:
    panic("license is invalid!")
  }

  fmt.Println("License is activated!")
}
```

### Automatic Upgrades

Check for an upgrade and automatically replace the current binary with the newest version.

```go
package main

import "github.com/keygen-sh/keygen-go/v2"

// The current version of the program
const CurrentVersion = "1.0.0"

func main() {
  keygen.PublicKey = "YOUR_KEYGEN_PUBLIC_KEY"
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "key/..."

  fmt.Printf("Current version: %s\n", CurrentVersion)
  fmt.Println("Checking for upgrades...")

  opts := keygen.UpgradeOptions{CurrentVersion: CurrentVersion, Channel: "stable", PublicKey: "YOUR_COMPANY_PUBLIC_KEY"}

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
    panic("upgrade install failed!")
  }

  fmt.Printf("Upgrade complete! Installed version: %s\n", release.Version)
  fmt.Println("Restart to finish installation...")
}
```

### Monitor Machine Heartbeats

Monitor a machine's heartbeat, and automatically deactivate machines in case of a crash
or an unresponsive node. We recommend using a random UUID fingerprint for activating
nodes in cloud-based scenarios, since nodes may share underlying hardware.

```go
package main

import (
  "github.com/google/uuid"
  "github.com/keygen-sh/keygen-go/v2"
)

func main() {
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "key/..."

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
      fmt.Println("machine activation failed!")

      panic(err)
    }

    // Handle SIGINT and gracefully deactivate the machine
    sigs := make(chan os.Signal, 1)

    signal.Notify(sigs, os.Interrupt)

    go func() {
      for sig := range sigs {
        fmt.Printf("Caught %v, deactivating machine and gracefully exiting...\n", sig)

        if err := machine.Deactivate(); err != nil {
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

import "github.com/keygen-sh/keygen-go/v2"

func main() {
  keygen.PublicKey = "YOUR_KEYGEN_PUBLIC_KEY"

  // Read the license file
  cert, err := ioutil.ReadFile("/etc/example/license.lic")
  if err != nil {
    panic("license file is missing")
  }

  // Verify the license file's signature
  lic := &keygen.LicenseFile{Certificate: string(cert)}
  err = lic.Verify()
  switch {
  case err == keygen.ErrLicenseFileNotGenuine:
    panic("license file is not genuine!")
  case err != nil:
    panic(err)
  }

  // Use the license key to decrypt the license file
  dataset, err := lic.Decrypt("key/...")
  switch {
  case err == ErrSystemClockUnsynced:
    panic("system clock tampering detected!")
  case err == ErrLicenseFileExpired:
    panic("license file is expired!")
  case err != nil:
    panic(err)
  }

  fmt.Println("License file is genuine!")
  fmt.Printf("Decrypted dataset: %v\n", dataset)
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

import "github.com/keygen-sh/keygen-go/v2"

func main() {
  keygen.PublicKey = "YOUR_KEYGEN_PUBLIC_KEY"

  // Verify the license key's signature and decode embedded dataset
  license := &keygen.License{Scheme: keygen.SchemeCodeEd25519, Key: "key/..."}
  dataset, err := license.Verify()
  switch {
  case err == keygen.ErrLicenseKeyNotGenuine:
    panic("license key is not genuine!")
  case err != nil:
    panic(err)
  }

  fmt.Println("License is genuine!")
  fmt.Printf("Decoded dataset: %s\n", dataset)
}
```

### Verify Webhooks

When listening for webhook events from Keygen, you can verify requests came from
Keygen's servers by using `keygen.VerifyWebhook`. This protects your webhook
endpoint from event forgery and replay attacks.

Requires that `keygen.PublicKey` is set.

```go
package main

import (
  "log"
  "net/http"

  "github.com/keygen-sh/keygen-go/v2"
)

func main() {
  keygen.PublicKey = "YOUR_KEYGEN_PUBLIC_KEY"

  http.HandleFunc("/webhooks", func(w http.ResponseWriter, r *http.Request) {
    if err := keygen.VerifyWebhook(r); err != nil {
      w.WriteHeader(http.StatusBadRequest)

      return
    }

    w.WriteHeader(http.StatusNoContent)
  })

  log.Fatal(http.ListenAndServe(":8081", nil))
}
```

## Error Handling

Our SDK tries to return meaningful errors which can be handled in your integration. Below
are a handful of error recipes that can be used for the more common errors.

### Invalid License Key

When authenticating with a license key, you may receive a `LicenseKeyError` when the license
key does not exist. You can handle this accordingly.

```go
package main

import "github.com/keygen-sh/keygen-go/v2"

func getLicense() (*keygen.License, error) {
  keygen.LicenseKey = promptForLicenseKey()

  license, err := keygen.Validate()
  if err != nil {
    if _, ok := err.(*keygen.LicenseKeyError); ok {
      fmt.Println("License key does not exist!")

      return getLicense()
    }

    return nil, err
  }

  return license, nil
}

func main() {
  keygen.Account = "..."
  keygen.Product = "..."

  license, err := getLicense()
  if err != nil {
    panic(err)
  }

  fmt.Printf("License: %v\n", license)
}
```

### Invalid License Token

When authenticating with a license token, you may receive a `LicenseTokenError` when the license
token does not exist or has expired. You can handle this accordingly.

```go
package main

import "github.com/keygen-sh/keygen-go/v2"

func getLicense() (*keygen.License, error) {
  keygen.Token = promptForLicenseToken()

  license, err := keygen.Validate()
  if err != nil {
    if _, ok := err.(*keygen.LicenseTokenError); ok {
      fmt.Println("License token does not exist!")

      return getLicense()
    }

    return nil, err
  }

  return license, nil
}

func main() {
  keygen.Account = "..."
  keygen.Product = "..."

  license, err := getLicense()
  if err != nil {
    panic(err)
  }

  fmt.Printf("License: %v\n", license)
}
```

### Rate Limiting

When your integration makes too many requests too quickly, the IP address may be [rate limited](https://keygen.sh/docs/api/rate-limiting/).
You can handle this via the `RateLimitError` error. For example, you could use this error to
determine how long to wait before retrying a request.

```go
package main

import "github.com/keygen-sh/keygen-go/v2"

func validate() (*keygen.License, error) {
  license, err := keygen.Validate()
  if err != nil {
    if e, ok := err.(*keygen.RateLimitError); ok {
      // Sleep until our rate limit window is passed
      time.Sleep(time.Duration(e.RetryAfter) * time.Second)

      // Retry validate
      return validate()
    }

    return nil, err
  }

  return license, nil
}

func main() {
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "key/..."

  license, err := validate()
  if err != nil {
    panic(err)
  }

  fmt.Printf("License: %v\n", license)
}
```

You may want to add a limit to the number of retry attempts.

### Automatic retries

When your integration has less-than-stellar network connectivity, or you simply want to
ensure that failed requests are retried, you can utilize a package such as [retryablehttp](github.com/hashicorp/go-retryablehttp)
to implement automatic retries.

```go
package main

import (
  "github.com/hashicorp/go-retryablehttp"
  "github.com/keygen-sh/keygen-go/v2"
)

func main() {
  c := retryablehttp.NewClient()

  // Configure with a jitter backoff and max attempts
	c.Backoff = retryablehttp.LinearJitterBackoff
	c.RetryMax = 5

	keygen.HTTPClient = c.StandardClient()
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "key/..."

  // Use SDK as you would normally
  keygen.Validate()
}
```
