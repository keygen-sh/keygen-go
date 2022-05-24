package keygen

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidate(t *testing.T) {
	log := Logger.(*LeveledLogger)
	log.Level = LogLevelDebug

	PublicKey = os.Getenv("KEYGEN_PUBLIC_KEY")
	Account = os.Getenv("KEYGEN_ACCOUNT")
	Product = os.Getenv("KEYGEN_PRODUCT")
	LicenseKey = os.Getenv("KEYGEN_LICENSE_KEY")
	Token = os.Getenv("KEYGEN_TOKEN")

	Executable = "sdk"
	Platform = "test"

	fingerprint := uuid.New().String()
	license, err := Validate(fingerprint)
	switch {
	case err == ErrLicenseTokenInvalid:
		t.Fatalf("Should be a valid license token: err=%v", err)
	case err == ErrLicenseKeyInvalid:
		t.Fatalf("Should be a valid license key: err=%v", err)
	case err == ErrLicenseInvalid:
		t.Fatalf("Should be a valid license: err=%v", err)
	case err == ErrLicenseNotActivated:
		if license.ID == "" {
			t.Fatalf("Should have a correctly set license ID: license=%v", license)
		}

		if ts := license.LastValidated; ts == nil || time.Now().Add(time.Duration(-time.Second)).After(*ts) {
			t.Fatalf("Should have a correct last validated timestamp: ts=%v", ts)
		}

		key, err := license.Verify()
		switch {
		case err == ErrLicenseKeyNotGenuine:
			t.Fatalf("Should be a genuine license key: err=%v", err)
		case err != nil:
			t.Fatalf("Should not fail genuine check: err=%v", err)
		}

		lic, err := license.Checkout()
		if err != nil {
			t.Fatalf("Should not fail checkout: err=%v", err)
		}

		err = lic.Verify()
		switch {
		case err == ErrLicenseFileNotGenuine:
			t.Fatalf("Should be a genuine license file: err=%v", err)
		case err != nil:
			t.Fatalf("Should not fail genuine check: err=%v", err)
		}

		info, err := lic.Decrypt()
		if err != nil {
			t.Fatalf("Should not fail decrypt: err=%v", err)
		}

		switch {
		case info.License.ID != license.ID:
			t.Fatalf("Should have the correct license ID: actual=%s expected=%s", info.License.ID, license.ID)
		case len(info.Entitlements) == 0:
			t.Fatalf("Should have at least 1 entitlement: entitlements=%s", info.Entitlements)
		case info.Issued.IsZero():
			t.Fatalf("Should have an issued timestamp: ts=%v", info.Issued)
		case info.Expiry.IsZero():
			t.Fatalf("Should have an expiry timestamp: ts=%v", info.Expiry)
		case info.TTL == 0:
			t.Fatalf("Should have a TTL: ttl=%d", info.TTL)
		}

		machine, err := license.Activate(fingerprint)
		if err != nil {
			t.Fatalf("Should not fail activation: err=%v", err)
		}

		mic, err := machine.Checkout()
		if err != nil {
			t.Fatalf("Should not fail checkout: err=%v", err)
		}

		err = mic.Verify()
		switch {
		case err == ErrLicenseFileNotGenuine:
			t.Fatalf("Should be a genuine machine file: err=%v", err)
		case err != nil:
			t.Fatalf("Should not fail genuine check: err=%v", err)
		}

		info2, err := mic.Decrypt()
		if err != nil {
			t.Fatalf("Should not fail decrypt: err=%v", err)
		}

		switch {
		case info2.Machine.ID != machine.ID:
			t.Fatalf("Should have the correct machine ID: actual=%s expected=%s", info2.Machine.ID, machine.ID)
		case info2.License.ID != license.ID:
			t.Fatalf("Should have the correct license ID: actual=%s expected=%s", info2.License.ID, license.ID)
		case len(info2.Entitlements) == 0:
			t.Fatalf("Should have at least 1 entitlement: entitlements=%s", info2.Entitlements)
		case info2.Issued.IsZero():
			t.Fatalf("Should have an issued timestamp: ts=%v", info2.Issued)
		case info2.Expiry.IsZero():
			t.Fatalf("Should have an expiry timestamp: ts=%v", info2.Expiry)
		case info2.TTL == 0:
			t.Fatalf("Should have a TTL: ttl=%d", info2.TTL)
		}

		// _, err = license.Activate(fingerprint)
		// switch {
		// case err == nil:
		// 	t.Fatalf("Should not be activated again: license=%v fingerprint=%s", license, fingerprint)
		// case err != ErrMachineAlreadyActivated:
		// 	t.Fatalf("Should fail duplicate activation: err=%v", err)
		// }

		another := uuid.New().String()
		_, err = license.Activate(another)
		switch {
		case err == nil:
			t.Fatalf("Should not allow a second activation: license=%v fingerprint=%s", license, another)
		case err != ErrMachineLimitExceeded:
			t.Fatalf("Should fail second activation: err=%v", err)
		}

		err = machine.Monitor()
		if err != nil {
			t.Fatalf("Should not fail to send first hearbeat ping: err=%v", err)
		}

		if machine.HeartbeatStatus != HeartbeatStatusCodeAlive {
			t.Fatalf("Should have a heartbeat that is alive: license=%v machine=%v", license, machine)
		}

		processes := []*Process{}

		for i := 0; i < 5; i++ {
			process, err := machine.Spawn(fmt.Sprintf("proc-%d", i))
			if err != nil {
				t.Fatalf("Should not fail spawning process: err=%v", err)
			}

			if process.Status != ProcessStatusCodeAlive {
				t.Fatalf("Should have a heartbeat that is alive: license=%v machine=%v process=%v", license, machine, process)
			}

			processes = append(processes, process)
		}

		for _, process := range processes {
			err = process.Kill()
			if err != nil {
				t.Fatalf("Should not fail killing process: err=%v", err)
			}
		}

		_, err = license.Machine(fingerprint)
		if err != nil {
			t.Fatalf("Should not fail to retrieve the current machine: err=%v", err)
		}

		machines, err := license.Machines()
		if err != nil {
			t.Fatalf("Should not fail to list machines: err=%v", err)
		}

		_, err = Validate(fingerprint)
		if err != nil {
			t.Fatalf("Should not fail revalidation: err=%v", err)
		}

		for _, machine := range machines {
			err = machine.Deactivate()
			if err != nil {
				t.Fatalf("Should not fail deactivation: err=%v", err)
			}
		}

		err = license.Deactivate(fingerprint)
		switch {
		case err == nil:
			t.Fatalf("Should not be deactivated again: license=%v fingerprint=%s", license, fingerprint)
		case err != ErrNotFound:
			t.Fatalf("Should already be deactivated: err=%v", err)
		}

		entitlements, err := license.Entitlements()
		if err != nil {
			t.Fatalf("Should not fail to list entitlements: err=%v", err)
		}

		t.Logf("license=%v machines=%v entitlements=%v key=%s lic=%v", license, machines, entitlements, key, info)
	case err != nil:
		t.Fatalf("Should not fail validation: err=%v", err)
	case err == nil:
		t.Fatalf("Should not be activated: err=%v", err)
	}
}

func TestUpgrade(t *testing.T) {
	Account = os.Getenv("KEYGEN_ACCOUNT")
	Product = os.Getenv("KEYGEN_PRODUCT")
	LicenseKey = os.Getenv("KEYGEN_LICENSE_KEY")
	Token = os.Getenv("KEYGEN_TOKEN")

	upgrade, err := Upgrade("1.0.0")
	switch {
	case err == ErrUpgradeNotAvailable:
		t.Fatalf("Should have an upgrade available: err=%v", err)
	case err != nil:
		t.Fatalf("Should not fail upgrade: err=%v", err)
	}

	err = upgrade.Install()
	if err != nil {
		t.Fatalf("Should not fail installing upgrade: err=%v", err)
	}

	t.Logf("upgrade=%v", upgrade)
}
