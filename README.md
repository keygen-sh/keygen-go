# Keygen Go SDK

[![godoc reference](https://godoc.org/github.com/keygen-sh/keygen-go/v3?status.png)](https://godoc.org/github.com/keygen-sh/keygen-go/v3)
[![CI](https://github.com/keygen-sh/keygen-go/actions/workflows/test.yml/badge.svg)](https://github.com/keygen-sh/keygen-go/actions)

Package [`keygen`](https://pkg.go.dev/github.com/keygen-sh/keygen-go/v3) allows Go programs to
license and remotely update themselves using the [keygen.sh](https://keygen.sh) service.

## Installing

```
go get github.com/keygen-sh/keygen-go/v3
```

## Config

### keygen.Account

`Account` is your Keygen account ID used globally in the SDK. All requests will be made
to this account. This should be hard-coded into your app.

```go
keygen.Account = "1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"
```

### keygen.Product

`Product` is your Keygen product ID used globally in the SDK. All license validations and
upgrade requests will be scoped to this product. This should be hard-coded into your app.

```go
keygen.Product = "1f086ec9-a943-46ea-9da4-e62c2180c2f4"
```

### keygen.LicenseKey

`LicenseKey` is a license key belonging to the end-user (licensee). This will be used for license
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

The `Validate` method accepts zero or more fingerprints, which can be used to scope a
license validation to a particular device fingerprint and its hardware components.
The first fingerprint should be a machine fingerprint, and the rest are optional
component fingerprints.

It will return a `License` object as well as any validation errors that occur. The `License`
object can be used to perform additional actions, such as `license.Activate(fingerprint)`.

```go
ctx := context.Background()
license, err := keygen.Validate(ctx, fingerprint)
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

ctx := context.Background()

// Check for an upgrade
release, err := keygen.Upgrade(ctx, opts)
switch {
case err == keygen.ErrUpgradeNotAvailable:
  fmt.Println("No upgrade available, already at the latest version!")

  return
case err != nil:
  fmt.Println("Upgrade check failed!")

  return
}

// Install the upgrade
if err := release.Install(ctx); err != nil {
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
  "context"

  "github.com/denisbrodbeck/machineid"
  "github.com/keygen-sh/keygen-go/v3"
)

func main() {
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "A_KEYGEN_LICENSE_KEY"

  fingerprint, err := machineid.ProtectedID(keygen.Product)
  if err != nil {
    panic(err)
  }

  ctx := context.Background()

  // Validate the license for the current fingerprint
  license, err := keygen.Validate(ctx, fingerprint)
  switch {
  case err == keygen.ErrLicenseNotActivated:
    // Activate the current fingerprint
    machine, err := license.Activate(ctx, fingerprint)
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

import (
  "context"

  "github.com/keygen-sh/keygen-go/v3"
)

// The current version of the program
const CurrentVersion = "1.0.0"

func main() {
  keygen.PublicKey = "YOUR_KEYGEN_PUBLIC_KEY"
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "A_KEYGEN_LICENSE_KEY"

  fmt.Printf("Current version: %s\n", CurrentVersion)
  fmt.Println("Checking for upgrades...")

  ctx := context.Background()

  opts := keygen.UpgradeOptions{CurrentVersion: CurrentVersion, Channel: "stable", PublicKey: "YOUR_COMPANY_PUBLIC_KEY"}

  // Check for upgrade
  release, err := keygen.Upgrade(ctx, opts)
  switch {
  case err == keygen.ErrUpgradeNotAvailable:
    fmt.Println("No upgrade available, already at the latest version!")

    return
  case err != nil:
    fmt.Println("Upgrade check failed!")

    return
  }

  fmt.Printf("Upgrade available! Newest version: %s\n", release.Version)
  fmt.Println("Installing upgrade...")

  // Download the upgrade and install it
  err = release.Install(ctx)
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
  "context"

  "github.com/google/uuid"
  "github.com/keygen-sh/keygen-go/v3"
)

func main() {
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "A_KEYGEN_LICENSE_KEY"

  // The current device's fingerprint (could be e.g. MAC, mobo ID, GUID, etc.)
  fingerprint := uuid.New().String()

  ctx := context.Background()

  // Keep our example process alive
  done := make(chan bool, 1)

  // Validate the license for the current fingerprint
  license, err := keygen.Validate(ctx, fingerprint)
  switch {
  case err == keygen.ErrLicenseNotActivated:
    // Activate the current fingerprint
    machine, err := license.Activate(ctx, fingerprint)
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

        if err := machine.Deactivate(ctx); err != nil {
          panic(err)
        }

        fmt.Println("Machine was deactivated!")
        fmt.Println("Exiting...")

        done <- true
      }
    }()

    // Start a heartbeat monitor for the current machine
    if err := machine.Monitor(ctx); err != nil {
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

import "github.com/keygen-sh/keygen-go/v3"

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
  dataset, err := lic.Decrypt("A_KEYGEN_LICENSE_KEY")
  switch {
  case err == keygen.ErrSystemClockUnsynced:
    panic("system clock tampering detected!")
  case err == keygen.ErrLicenseFileExpired:
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

import "github.com/keygen-sh/keygen-go/v3"

func main() {
  keygen.PublicKey = "YOUR_KEYGEN_PUBLIC_KEY"

  // Verify the license key's signature and decode embedded dataset
  license := &keygen.License{Scheme: keygen.SchemeCodeEd25519, Key: "A_SIGNED_KEYGEN_LICENSE_KEY"}
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

  "github.com/keygen-sh/keygen-go/v3"
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

import (
  "context"
  
  "github.com/keygen-sh/keygen-go/v3"
)

func getLicense(ctx context.Context) (*keygen.License, error) {
  keygen.LicenseKey = promptForLicenseKey()

  license, err := keygen.Validate(ctx)
  if err != nil {
    if _, ok := err.(*keygen.LicenseKeyError); ok {
      fmt.Println("License key does not exist!")

      return getLicense(ctx)
    }

    return nil, err
  }

  return license, nil
}

func main() {
  keygen.Account = "..."
  keygen.Product = "..."

  ctx := context.Background()

  license, err := getLicense(ctx)
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

import "github.com/keygen-sh/keygen-go/v3"

func getLicense(ctx context.Context) (*keygen.License, error) {
  keygen.Token = promptForLicenseToken()

  license, err := keygen.Validate(ctx)
  if err != nil {
    if _, ok := err.(*keygen.LicenseTokenError); ok {
      fmt.Println("License token does not exist!")

      return getLicense(ctx)
    }

    return nil, err
  }

  return license, nil
}

func main() {
  keygen.Account = "..."
  keygen.Product = "..."

  ctx := context.Background()

  license, err := getLicense(ctx)
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

import "github.com/keygen-sh/keygen-go/v3"

func validate(ctx context.Context) (*keygen.License, error) {
  license, err := keygen.Validate(ctx)
  if err != nil {
    if e, ok := err.(*keygen.RateLimitError); ok {
      // Sleep until our rate limit window is passed
      time.Sleep(time.Duration(e.RetryAfter) * time.Second)

      // Retry validate
      return validate(ctx)
    }

    return nil, err
  }

  return license, nil
}

func main() {
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "A_KEYGEN_LICENSE_KEY"

  ctx := context.Background()

  license, err := validate(ctx)
  if err != nil {
    panic(err)
  }

  fmt.Printf("License: %v\n", license)
}
```

You may want to add a limit to the number of retry attempts.

### Automatic retries

When your integration has less-than-stellar network connectivity, or you simply want to
ensure that failed requests are retried, you can utilize a package such as [`retryablehttp`](https://github.com/hashicorp/go-retryablehttp)
to implement automatic retries.

```go
package main

import (
  "context"

  "github.com/hashicorp/go-retryablehttp"
  "github.com/keygen-sh/keygen-go/v3"
)

func main() {
  c := retryablehttp.NewClient()

  // Configure with a jitter backoff and max attempts
  c.Backoff = retryablehttp.LinearJitterBackoff
  c.RetryMax = 5

  keygen.HTTPClient = c.StandardClient()
  keygen.Account = "YOUR_KEYGEN_ACCOUNT_ID"
  keygen.Product = "YOUR_KEYGEN_PRODUCT_ID"
  keygen.LicenseKey = "A_KEYGEN_LICENSE_KEY"

  ctx := context.Background()

  // Use SDK as you would normally
  keygen.Validate(ctx)
}
```

## Testing

When implementing a testing strategy for your licensing integration, we recommend that you
fully mock our APIs. This is especially important for CI/CD environments, to prevent
unneeded load on our servers. Mocking our APIs will also allow you to more easily
stay within your account's daily request limits.

To do so in Go, you can utilize [`gock`](https://github.com/h2non/gock) or [`httptest`](https://pkg.go.dev/net/http/httptest).

```go
package main

import (
  "context"
  "testing"

  "github.com/keygen-sh/keygen-go/v3"
  "gopkg.in/h2non/gock.v1"
)

func init() {
  keygen.PublicKey = "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788"
  keygen.Account = "1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"
  keygen.Product = "1f086ec9-a943-46ea-9da4-e62c2180c2f4"
  keygen.LicenseKey = "C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3"
}

func TestExample(t *testing.T) {
  ctx := context.Background()
  defer gock.Off()

  // Intercept Keygen's HTTP client
  gock.InterceptClient(keygen.HTTPClient)
  defer gock.RestoreClient(keygen.HTTPClient)

  // Mock endpoints
  gock.New("https://api.keygen.sh").
    Get(`/v1/accounts/([^\/]+)/me`).
    Reply(200).
    SetHeader("Keygen-Signature", `keyid="1fddcec8-8dd3-4d8d-9b16-215cac0f9b52", algorithm="ed25519", signature="IiyYX1ah2HFzbcCx+3sv+KJpOppFdMRuZ7NWlnwZMKAf5khj9c4TO4z6fr62BqNXlyROOTxZinX8UpXHJHVyAw==", headers="(request-target) host date digest"`).
    SetHeader("Digest", "sha-256=d4uZ26hjiUNqopuSkYcYwg2aBuNtr4D1/9iDhlvf0H8=").
    SetHeader("Date", "Wed, 15 Jun 2022 18:52:14 GMT").
    BodyString(`{"data":{"id":"218810ed-2ac8-4c26-a725-a6da67500561","type":"licenses","attributes":{"name":"Demo License","key":"C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3","expiry":null,"status":"ACTIVE","uses":0,"suspended":false,"scheme":null,"encrypted":false,"strict":false,"floating":false,"concurrent":false,"protected":true,"maxMachines":1,"maxProcesses":null,"maxCores":null,"maxUses":null,"requireHeartbeat":false,"requireCheckIn":false,"lastValidated":"2022-06-15T18:52:12.068Z","lastCheckIn":null,"nextCheckIn":null,"metadata":{"email":"user@example.com"},"created":"2020-09-14T21:18:08.990Z","updated":"2022-06-15T18:52:12.073Z"},"relationships":{"account":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"},"data":{"type":"accounts","id":"1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"}},"product":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/product"},"data":{"type":"products","id":"ef6e0993-70d6-42c4-a0e8-846cb2e3fa54"}},"policy":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/policy"},"data":{"type":"policies","id":"629307fb-331d-430b-978a-44d45d9de133"}},"group":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/group"},"data":null},"user":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/user"},"data":null},"machines":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/machines"},"meta":{"cores":0,"count":1}},"tokens":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/tokens"}},"entitlements":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/entitlements"}}},"links":{"self":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561"}}}`)

  gock.New("https://api.keygen.sh").
    Post(`/v1/accounts/([^\/]+)/licenses/([^\/]+)/actions/validate`).
    Reply(200).
    SetHeader("Keygen-Signature", `keyid="1fddcec8-8dd3-4d8d-9b16-215cac0f9b52", algorithm="ed25519", signature="18+5Q4749BKuUz9/f35UrdP5g3Pyt32pPN3J8e5BqSlRbqiXnz0HwtqbP5sbvGkq1yixelwgV6bcJ0WUtpDSBw==", headers="(request-target) host date digest"`).
    SetHeader("Digest", "sha-256=c1y1CVVLG0mvt0MP1SJy/bOiNjCytxMOuHUhlCXXVVk=").
    SetHeader("Date", "Thu, 09 Feb 2023 21:20:13 GMT").
    BodyString(`{"data":{"id":"218810ed-2ac8-4c26-a725-a6da67500561","type":"licenses","attributes":{"name":"Demo License","key":"C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3","expiry":null,"status":"ACTIVE","uses":0,"suspended":false,"scheme":null,"encrypted":false,"strict":false,"floating":false,"protected":true,"maxMachines":1,"maxProcesses":null,"maxCores":null,"maxUses":null,"requireHeartbeat":false,"requireCheckIn":false,"lastValidated":"2023-02-09T21:20:13.679Z","lastCheckIn":null,"nextCheckIn":null,"lastCheckOut":null,"metadata":{"email":"user@example.com"},"created":"2020-09-14T21:18:08.990Z","updated":"2023-02-09T21:20:13.691Z"},"relationships":{"account":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"},"data":{"type":"accounts","id":"1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"}},"product":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/product"},"data":{"type":"products","id":"ef6e0993-70d6-42c4-a0e8-846cb2e3fa54"}},"policy":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/policy"},"data":{"type":"policies","id":"629307fb-331d-430b-978a-44d45d9de133"}},"group":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/group"},"data":null},"user":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/user"},"data":null},"machines":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/machines"},"meta":{"cores":0,"count":1}},"tokens":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/tokens"}},"entitlements":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/entitlements"}}},"links":{"self":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561"}},"meta":{"ts":"2023-02-09T21:20:13.696Z","valid":true,"detail":"is valid","code":"VALID"}}`)

  // Allow old response signatures
  keygen.MaxClockDrift = -1

  // Use SDK as you would normally
  _, err := keygen.Validate(ctx)
  if err != nil {
    t.Fatalf("Should not fail mock validation: err=%v", err)
  }
}
```
