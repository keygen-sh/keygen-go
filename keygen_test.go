package keygen

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
)

func init() {
	log := Logger.(*logger)
	log.Level = LogLevelDebug

	if url := os.Getenv("KEYGEN_CUSTOM_DOMAIN"); url != "" {
		APIURL = url
	}

	PublicKey = os.Getenv("KEYGEN_PUBLIC_KEY")
	Environment = os.Getenv("KEYGEN_ENVIRONMENT_ID")
	Account = os.Getenv("KEYGEN_ACCOUNT_ID")
	Product = os.Getenv("KEYGEN_PRODUCT_ID")
	LicenseKey = os.Getenv("KEYGEN_LICENSE_KEY")
	Token = os.Getenv("KEYGEN_LICENSE_TOKEN")
	Logger = log
}

func TestValidate(t *testing.T) {
	fingerprint, err := machineid.ProtectedID(Account)
	if err != nil {
		t.Fatalf("Should fingerprint the current machine: err=%v", err)
	}

	if _, err := Validate(); err != ErrValidationFingerprintMissing {
		t.Fatalf("Should have a required scope: err=%v", err)
	}

	license, err := Validate(fingerprint)
	if err == nil {
		t.Fatalf("Should not be activated: err=%v", err)
	}

	switch err.(type) {
	case *LicenseTokenError:
		t.Fatalf("Should be a valid license token: err=%v", err)
	case *LicenseKeyError:
		t.Fatalf("Should be a valid license key: err=%v", err)
	case *RateLimitError:
		t.Fatalf("Should not be rate limited: err=%v", err)
	case *NotAuthorizedError:
		t.Fatalf("Should be authorized: err=%v", err)
	case *NotFoundError:
		t.Fatalf("Should exist: err=%v", err)
	}

	switch {
	case err == ErrLicenseInvalid:
		t.Fatalf("Should be a valid license: err=%v", err)
	case err == ErrLicenseNotActivated:
		switch {
		case license.LastValidation.Code != ValidationCodeNoMachine:
			t.Fatalf("Should store last validation code: code=%s", license.LastValidation.Code)
		case license.LastValidation.Valid:
			t.Fatalf("Should store last validation: valid=%t", license.LastValidation.Valid)
		case license.ID == "":
			t.Fatalf("Should have a correctly set license ID: license=%v", license)
		}

		if ts := license.LastValidated; ts == nil || time.Now().Add(time.Duration(-time.Second)).After(*ts) {
			t.Fatalf("Should have a correct last validated timestamp: ts=%v", ts)
		}

		{
			dataset, err := license.Verify()
			switch {
			case err == ErrLicenseKeyNotGenuine:
				t.Fatalf("Should be a genuine license key: err=%v", err)
			case err != nil:
				t.Fatalf("Should not fail genuine check: err=%v", err)
			}

			t.Logf("dataset=%v", dataset)
		}

		// defaults
		{
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

			dataset, err := lic.Decrypt(license.Key)
			if err != nil {
				t.Fatalf("Should not fail decrypt: err=%v", err)
			}

			switch {
			case dataset.License.ID != license.ID:
				t.Fatalf("Should have the correct license ID: actual=%s expected=%s", dataset.License.ID, license.ID)
			case len(dataset.Entitlements) == 0:
				t.Fatalf("Should have at least 1 entitlement: entitlements=%v", dataset.Entitlements)
			case dataset.Issued.IsZero():
				t.Fatalf("Should have an issued timestamp: ts=%v", dataset.Issued)
			case dataset.Expiry.IsZero():
				t.Fatalf("Should have an expiry timestamp: ts=%v", dataset.Expiry)
			case dataset.TTL == 0:
				t.Fatalf("Should have a TTL: ttl=%d", dataset.TTL)
			}

			t.Logf("dataset=%+v", dataset)
		}

		// options
		{
			lic, err := license.Checkout(
				CheckoutInclude(),
				CheckoutTTL(24*time.Hour),
			)
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

			dataset, err := lic.Decrypt(license.Key)
			if err != nil {
				t.Fatalf("Should not fail decrypt: err=%v", err)
			}

			switch {
			case dataset.License.ID != license.ID:
				t.Fatalf("Should have the correct license ID: actual=%s expected=%s", dataset.License.ID, license.ID)
			case len(dataset.Entitlements) != 0:
				t.Fatalf("Should have no entitlements: entitlements=%v", dataset.Entitlements)
			case dataset.Issued.IsZero():
				t.Fatalf("Should have an issued timestamp: ts=%v", dataset.Issued)
			case time.Until(dataset.Expiry) > 24*time.Hour+30*time.Second: // 30s for network lag
				t.Fatalf("Should have an expiry timestamp: ts=%v", dataset.Expiry)
			case dataset.TTL == 0:
				t.Fatalf("Should have a TTL: ttl=%d", dataset.TTL)
			}

			t.Logf("dataset=%+v", dataset)
		}

		machine, err := license.Activate(fingerprint)
		if err != nil {
			t.Fatalf("Should not fail activation: err=%v", err)
		}

		// defaults
		{
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

			dataset, err := mic.Decrypt(license.Key + machine.Fingerprint)
			if err != nil {
				t.Fatalf("Should not fail decrypt: err=%v", err)
			}

			switch {
			case dataset.Machine.ID != machine.ID:
				t.Fatalf("Should have the correct machine ID: actual=%s expected=%s", dataset.Machine.ID, machine.ID)
			case dataset.License.ID != license.ID:
				t.Fatalf("Should have the correct license ID: actual=%s expected=%s", dataset.License.ID, license.ID)
			case len(dataset.Entitlements) == 0:
				t.Fatalf("Should have at least 1 entitlement: entitlements=%v", dataset.Entitlements)
			case dataset.Issued.IsZero():
				t.Fatalf("Should have an issued timestamp: ts=%v", dataset.Issued)
			case dataset.Expiry.IsZero():
				t.Fatalf("Should have an expiry timestamp: ts=%v", dataset.Expiry)
			case dataset.TTL == 0:
				t.Fatalf("Should have a TTL: ttl=%d", dataset.TTL)
			}

			t.Logf("dataset=%+v", dataset)
		}

		// options
		{
			mic, err := machine.Checkout(
				CheckoutInclude("license", "components"),
				CheckoutTTL(24*time.Hour*365),
			)
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

			dataset, err := mic.Decrypt(license.Key + machine.Fingerprint)
			if err != nil {
				t.Fatalf("Should not fail decrypt: err=%v", err)
			}

			switch {
			case dataset.Machine.ID != machine.ID:
				t.Fatalf("Should have the correct machine ID: actual=%s expected=%s", dataset.Machine.ID, machine.ID)
			case dataset.License.ID != license.ID:
				t.Fatalf("Should have the correct license ID: actual=%s expected=%s", dataset.License.ID, license.ID)
			case len(dataset.Entitlements) != 0:
				t.Fatalf("Should have no entitlements: entitlements=%v", dataset.Entitlements)
			case len(dataset.Components) != 0:
				t.Fatalf("Should have no components: components=%v", dataset.Components)
			case dataset.Issued.IsZero():
				t.Fatalf("Should have an issued timestamp: ts=%v", dataset.Issued)
			case time.Until(dataset.Expiry) < 24*time.Hour*365:
				t.Fatalf("Should have an expiry timestamp: ts=%v", dataset.Expiry)
			case dataset.TTL == 0:
				t.Fatalf("Should have a TTL: ttl=%d", dataset.TTL)
			}

			t.Logf("dataset=%+v", dataset)
		}

		// _, err = license.Activate(fingerprint)
		// switch {
		// case err == nil:
		// 	t.Fatalf("Should not be activated again: license=%v fingerprint=%s", license, fingerprint)
		// case err != ErrMachineAlreadyActivated:
		// 	t.Fatalf("Should fail duplicate activation: err=%v", err)
		// }

		_, err = license.Activate(uuid.New().String())
		if err != ErrMachineLimitExceeded {
			t.Fatalf("Should fail over-limit activation: license=%v err=%v", license, err)
		}

		// Check if there are any race conditions
		for i := 0; i <= 5; i++ {
			go license.Machine(machine.Fingerprint)
		}

		err = machine.Monitor()
		if err != nil {
			t.Fatalf("Should not fail to send first hearbeat ping: err=%v", err)
		}

		if machine.HeartbeatStatus != HeartbeatStatusCodeAlive {
			t.Fatalf("Should have a heartbeat that is alive: license=%v machine=%v", license, machine)
		}

		if !machine.RequireHeartbeat {
			t.Fatalf("Should require a heartbeat: license=%v machine=%v", license, machine)
		}

		processes := []*Process{}

		for i := 0; i < 5; i++ {
			process, err := machine.Spawn(uuid.New().String())
			if err != nil {
				t.Fatalf("Should not fail spawning process: err=%v", err)
			}

			if process.Status != ProcessStatusCodeAlive {
				t.Fatalf("Should have a heartbeat that is alive: license=%v machine=%v process=%v", license, machine, process)
			}

			processes = append(processes, process)
		}

		_, err = machine.Spawn(uuid.New().String())
		if err != ErrProcessLimitExceeded {
			t.Fatalf("Should fail over-limit spawn: machine=%v err=%v", machine, err)
		}

		procs, err := machine.Processes()
		if err != nil {
			t.Fatalf("Should not fail listing processes: err=%v", err)
		}

		if len(procs) != len(processes) {
			t.Fatalf("Should list all processes: actual=%v expected=%v", procs, processes)
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

		_, err = license.Machine("<invalid>")
		if err == nil {
			t.Fatalf("Should fail to retrieve invalid machine: err=%v", err)
		}

		machines, err := license.Machines()
		if err != nil {
			t.Fatalf("Should not fail to list machines: err=%v", err)
		}

		l, err := Validate(fingerprint)
		if err != nil {
			t.Fatalf("Should not fail revalidation: err=%v", err)
		}

		switch {
		case l.LastValidation.Code != ValidationCodeValid:
			t.Fatalf("Should store last revalidation code: code=%s", l.LastValidation.Code)
		case !l.LastValidation.Valid:
			t.Fatalf("Should store last revalidation: valid=%t", l.LastValidation.Valid)
		}

		for _, machine := range machines {
			err = machine.Deactivate()
			if err != nil {
				t.Fatalf("Should not fail deactivation: err=%v", err)
			}
		}

		err = license.Deactivate(fingerprint)
		if e, ok := err.(*NotFoundError); !ok {
			t.Fatalf("Should already be deactivated: err=%v", e)
		}

		entitlements, err := license.Entitlements()
		if err != nil {
			t.Fatalf("Should not fail to list entitlements: err=%v", err)
		}

		if len(entitlements) == 0 {
			t.Fatalf("Should have entitlements: entitlements=%v", entitlements)
		}

		// Components
		{
			board := uuid.NewString()
			disk := uuid.NewString()
			cpu := uuid.NewString()
			gpu := uuid.NewString()

			machine, err := license.Activate(fingerprint,
				Component{Name: "Board", Fingerprint: board},
				Component{Name: "Drive", Fingerprint: disk},
				Component{Name: "CPU", Fingerprint: cpu},
				Component{Name: "GPU", Fingerprint: gpu},
			)
			if err != nil {
				t.Fatalf("Should not fail reactivation: err=%v", err)
			}

			components, err := machine.Components()
			if err != nil {
				t.Fatalf("Should not fail to list components: err=%v", err)
			}

			if len(components) != 4 {
				t.Fatalf("Should have components: components=%v", components)
			}

			license, err = Validate(fingerprint, board, disk, gpu, cpu)
			if err != nil {
				t.Fatalf("Should be valid: err=%v", err)
			}

			switch {
			case license.LastValidation.Scope.Fingerprint != fingerprint:
				t.Fatalf("Should be scoped to fingerprint: scope=%v", license.LastValidation)
			case len(license.LastValidation.Scope.Components) != 4:
				t.Fatalf("Should be scoped to components: scope=%v", license.LastValidation)
			}

			if err := license.Validate(fingerprint, uuid.NewString()); err != ErrComponentNotActivated {
				t.Fatalf("Should be invalid: err=%v", err)
			}

			mic, err := machine.Checkout(
				CheckoutInclude("components", "license", "license.entitlements"),
			)
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

			dataset, err := mic.Decrypt(license.Key + machine.Fingerprint)
			if err != nil {
				t.Fatalf("Should not fail decrypt: err=%v", err)
			}

			switch {
			case dataset.Machine.ID != machine.ID:
				t.Fatalf("Should have the correct machine ID: actual=%s expected=%s", dataset.Machine.ID, machine.ID)
			case dataset.License.ID != license.ID:
				t.Fatalf("Should have the correct license ID: actual=%s expected=%s", dataset.License.ID, license.ID)
			case len(dataset.Entitlements) == 0:
				t.Fatalf("Should have entitlements: entitlements=%v", dataset.Entitlements)
			case len(dataset.Components) != 4:
				t.Fatalf("Should have components: components=%v", dataset.Components)
			case dataset.Issued.IsZero():
				t.Fatalf("Should have an issued timestamp: ts=%v", dataset.Issued)
			case dataset.Expiry.IsZero():
				t.Fatalf("Should have an expiry timestamp: ts=%v", dataset.Expiry)
			case dataset.TTL == 0:
				t.Fatalf("Should have a TTL: ttl=%d", dataset.TTL)
			}

			err = machine.Deactivate()
			if err != nil {
				t.Fatalf("Should not fail deactivation: err=%v", err)
			}
		}

		t.Logf(
			"license=%+v machines=%+v entitlements=%+v",
			license,
			machines,
			entitlements,
		)
	case err != nil:
		t.Fatalf("Should not fail validation: err=%v", err)
	}
}

func TestLicenseFile(t *testing.T) {
	lic := &LicenseFile{Certificate: "-----BEGIN LICENSE FILE-----\neyJlbmMiOiJDK2dneG5xRkJ6RURXMWc1YTBrUTE4OHBpdU9BL09vMkZDeUov\na2tlVk5QL3lJRTJGTVVXeXJZWUpzVGdmNXNIWFk3dko0My9Eb1JlRlluQ3VO\nSHprazFJOXZZdVpOWm9rWExSSHJvVkdxQXhBQ0pSN0R6dUJVTDk2bjI3VTcw\nNTRpR21DbjZOYmxVOVJzOUF0dGxRZ0kxZ2FNNUdaaE0walAzaGZvTnFkdzZu\nK3M2Y3M2Q2xRNGg5SmlEeTlvRGQzYmxFMEx4c0tYekhDS2graGtNSmtkbTZU\ndG9FWkU0eDdFOE4rWWNNM1hhdnJzSnNDL2k5MUdWQk9aT2pWZkdDNFg2dlV4\nK2RScGszT3dpMUF5QTh3MVRTazE3QVVaRlZrcVpiSEZyM2l0T3hxc0ZBbUNB\nWExVOTl4UzU2SGdWM0pZWGFVL2tKNTZETkhBOXNaTnVUcWxHR05sQXo5bUN0\nM1dGV1FNREQzdFdaelJqaUVRam9jOWppSEgvR3dFSlBZWjZPSmZVdXJuVnlr\ncllyTC92V3ZLeDRqRitJVS9rV1VPNmpBTnJMekpLMWVEalY0M2lpKzZxVytr\nNlQ2MC82N1hYVEUvczR0NG5FMDBHUmMvWGs3Vm5vc2VQbTh2eDMwVTI0YnhJ\nQjlxU3kwOTZncmhDYnJxQi9NNUJ5czlBdlFmSVdibDVZU0EyTUU3SG1uMVRS\nSThtMDI3YzdSUWtENDdveUxtbktRQmNEOExvczl4UEloYmJmOXhOKzlDY3VK\nN1ZaWFlLemdVQTZwQ0trTmFzK014T2F2VkQrbXZ2eHY4MjN0K2J4M2xxQndX\nbUFtckxXdTVoM2lQYjR2ZitaWHJPZUZhSzhpaElid0dYb1Vld0NLdkdwYmdV\nUGh4dXdmbTlaUjUzc1U1WVFNUFk5aGExd0dpcERycFpBaG5FSlZ6by9qY0Y5\nQzkvQ1ZxWGVpL1lWTktrZ3UwUk0zZFJ1ZUI3NkRPWmNjZkNXZXRPYklmS3dR\nODVWRVhzaUxSUWZkN3BSam5xa2ZRQnJVU0QvRlB2OXJPc2lNZkdSbmNSWlk0\nZU5WZXN6bEgyRXhXa1ZmNHBTcTg4cS9TVXU1UWZaV3pSNkhrTXR2MHRuVzd6\nMy9DOXRwb0JWc0VndlVFR0E4TW43eXpwQ0hXbmNWdWJNcy91bU16NWFGVFJq\nYjdhZUlVNitSYTBOcWhKOWtGc3pXb2E5MDNHZ0IxeENiMkdzSUxKVHpBQXM5\nd2NoRlQ4bThNQUNaNTRCMVM0SHN3VVJveGt0ZHBVcFZ4WFEyK1hDQjlBQjNM\nTkFIRlZlYjZyL0FtZW1vR082cG1VaGl5a0lJbmNlUm1YT3JzQzNKZWE4M1JI\nZmwrb1U5NXpFOUpjZTd0UDgwa0pxT2t5N3Z1MER0c0xPVkdMSm9WMEN6RVVn\nTDV6YlpwVDAyc2FzN21nYzd6Z1lKbVBxSzFVTWNvOWw2NXRFaHRxQ2g3WUlG\nenRkRGVMaUxXRTRlYjhIdUJGTmE4MkwzOWplajNtQythNDR5M1pwdElpcUY4\nM3ZjQTJCRk5qazdod0FDbmU1QmV5NDVHbnFwdzFRTjhXZmFUMk56djlTT0N3\nWE9TRG1HMzFrV3BPb05wM0tvYXJIeTZ2V280aVpqMlBDc3dpczkySi9GUDYv\nbnZvZFcrUFcrQnViV1pXWGhqRW1ibFZJUGQrTWdBU1FqcXJYRVRjNWc3QjJJ\nMW5icnM3SlExcXFrSDZoMG9WdzEzUTZRRE5DZWcvM2ZwZjk2ejIybmVIUFZY\neWkyNHR4WG5zWFZiZm1Rd3hoY1Y3WVFXMmR4UzVrTU13Q3dsTjA3dFNLSk44\ncmN5UUJ0SWNOcGp6M1FwWEovK2E1a1k2akJPV3VCczNuNU9PWjRoN0g3SHN0\nWDR0dG1zUXl3NC9hR1N1OUFpb2VpaWRzTmhqOWsvUlNzUUlYenhDQ2tMN2JX\nVlQreUVJeXowVTM0Tmp5NFl0aEk5K05pK1NnMU9aSlhPUXNNcmFYM29rdWNR\nNktldkduTTQ3SkVyTnJvY0Y1WlorOTBFcUxnZW1HdXB6Q3lnbHhpMDNjTytH\nWnJSZkMwWElma1JrSk5SMndQNDVtdlJSbUp3amY3OUhzNndpYnk4ZE9raW92\nRFRXRFdaNUp6NC9QN2JobE1vbHNoVTlOSStTbGtsbmM1bnJoaDErSjVyc09v\nQ0pNZ1N4WFh5cDBsUnN5eUFlQXlBd2JhdFdMbTJOeWwvb3dwTFpFd2NCczFE\neko4WjZiWTN6WGNEaklzR0Nlajh4cG9PcmtMRjVmT21vcS9nbStMNnpTc2tD\nVjVJWHBqRk1vaXBscU5ndGV3ZzhPOEQ5aFR2OUZUUWIxRWNvWlpnZkhUQUxt\nS1lTczRaUlY0T3U0R1pEdEVsVW04dXRLM3V0dzROcE43cWJQZGhDVVdnY0pi\nekhyR1h5M05vQWFXbVhFTGVpU1RsVmxKOFJSbGhUVm9nNms2eENFZVBOdEFC\nUmJURDJjKzdpNkR0UmttSXVsMmFFNkJSajB0R2Zlb3NvRUx4S0pOdS9keTBi\neTR2c3habkNLbnFtamVyazhUUTVuc0cwQzVMNURzVGhrc0dkNDVPV2RiK0dq\nbTFVRnNTaFRJNVZrbEx2UUVOQlFjTWJiR0tTWmE1UEdhOHBTMDQwVUNZRkt2\nd2ZMUWE1VVRlV0pmazFKTnZzU0V6VHVaMTQ4QkF5NjJ1T1RhMHNGaTU1SHdW\ncU51UkkyNzFjak1JdVdtYlZDa3ljSSs1ZWtDS0hCZ3FiMFkzY3RRbU9TQzh3\nNDdjMzBkUUFPYmRWYkdibTI2UTlaVVBWOUd3YUNIRjk5NWFLN3U4bURFbDlE\nMkRTb1UxenFHV0l1RVp2RDROblFqV2dRVHZZcE42Qkk4MmVONmZ2UkhEQTZS\nbTNiemRHQmFDUWNaSkdKOGt3YWVHVExjSnl5R29Sc3d5SEI3b1BHQjFhZXE0\na3ZwTjUrK3pBK1gwMGlxMVlIK0F0TFBSd0h6S21KSUIrbG05RXJObU1mNkFI\nMHhXcTF4RE9zSEhDT2lrQUlxeW9ZOHUwYWVocERDMWpvS3RPYWN0U21xbVBi\nc1lVSTNYZVo1Tnc4TVU5dkNvaytaaUhJYXZjWU9VUmR5cW1pemswVnI0bkhw\nTFowN3V5azEyL3pRdDBSRnVINWFjR25nVC9aRUo4eFVKS0lTYnkrT1UwUEpu\nTE5oQ2FmQ2ppTWNNU2xKNm5IZENHMlhtbEQ4ejFqR1ZHRmpRWE9DWkdsVU9m\neHc2Ynphc1h4c2NWNUVLdHpnN1lDY2k3bmpxWTM2K1A5SE0wMUNjVG9tVmpS\nSkw1aitnR1dNUzBQVmN0cTFDcG05SS9nUlZMMjhLZmZteW14anBWOFFuQVZk\nbmFNWVZhNGp0dGtHQ2liemUwQmFyckpyT0pUdG1qeUxyb3RhNU1Jb0dpdkFS\nMzFDSmRWYzBNRDRVRDVTTnhlcFZEZGtpbS91UFF3YjhoaWlsclRDWUhBNEZ5\nVU5nRTMxOFQrMHQ1R1ZlTXdCZkpzeDM1Zm1NSzRQV1R5eUdOcXVYQnlSVDJm\nYjBPa2RnSVVGc3NjY2xlaEt4RmdXdUZBNGxPZFQ4MGFHaHkxdUNkVkJrSnh0\neGtoRklzZ25TaDdSQUZqSVN1YWdIQ29XbXFZVTcrR1ZIVlBBVGtwU1AxWDhi\nbjVQRUlXNFhqVW1vNXNaS2QzYXFvKzM0N0JIaVpOVzRXSG9kWkZsSG41Ris1\nL28ydyt2R3R1S1JWYXZWTUMzR2hINEg5MzRodE5FbTJ5MWxwSUdyWkg4UFBW\nRG1qZDNTNGgwNWVtTUVSYnZWdFFkZTJBdktqUFc2R1hMR25IVTFsck5TaG80\nYnRtclZ6OVJGOHlkNEVhRG50dnVEL1laaFFMK3U1OWJDYXFvNm1FL0dLdFQz\nNU5LM1hxNjQ3Y254WDNHRytSa1Q4RTNNRXhOc05qZUs0K0ZWREhJWDlsWlNO\nNzVTZGhsd2lOY01ka3ZNNVUwY2Iwd2hlYUU5NEtjbUhCbXM1eDlBYWt1ZjdL\nT3A5NERXV0RzWGNsaVlEYzUrZWdMYVZqMmxLNkpPSUZja1dWWkhZeEI2bE16\nUkpsQVlmb2MwSDBDeFhjelhiRlNGQnc0bDVxS0Y1WjVSVHdEa1U4dlJ4Yytn\nYzRMQ3RybTRXV2p2ZmIxbmExMUUyVEt1UUh0MldhOHBpQlVYKzRLM09ONVY2\nemk5dXV0bktUR1F2K0tPd2Z5VndndTlrK0pOWEJFTUhDWUt6Y0hRZjBxUUZl\nUGd4Z3RWZmtEUFFjQS8wd29SVGVnZTR4KzV1YnVEYmRWZ1Z3N3JGY0t3Y1lF\nTXgwNmNDdUxCQWVFV3drWGp3TS9Dd0FPWWJvVFFQUmR4L3U4eXVSTnovK1Z5\nTWw3UjU4d05yQzl4MTRGQ0hLTmREc0MrSFpOWklTcXc3UGg0TGxLeEo3TXcr\ndjRyV1JGbEM2Yk5tZDJaUXdFWGN4NnJVbUpjTmV0WDl6bnNZT0FpV2p4eVNE\ncXo4MmJqUjlvUC8vTnl2emUrS1RTT3JaQmtnM3lRZGVLNTBCM0ZFSmRrQ1c2\nV09XMEdCQ1UzMXhqNWx1OVJLM0REMEI1bDRkRm9GNzlrNXZKdjFhdjQ3WmJr\neWIzRHFMcE00RkZyMWFpSE82dlFzWjcxUUtQbDY2czBlaXdTOXVZY2hXRHEv\nZmc0V3lXSlR5V3RlZUJnNGoxNGhUVm9JTnJnZ2pkME84eDN1VXRtVHA3R1hk\neWFmMWdCSFZXaCtRV1h0T2VMRHJaTDkvTjlSdWczcWFLeENwZlNLRmxRdXFJ\nQlFva1BYZXFVbjNDMkhrcWtwSmJTS3J3UDVJcUNXaEYwcXlqRFlXOWZUQzlN\nSWVjVHBFWVd2QUpkeU1DdW1jL3lMWHQ0bTlJVy9sbjd4bG5NaVlYanFZNWcz\nUDR2NlVtamdOc0x1QXVRQ3BadWplN1BDcXZLcThEMGc5SUhXTFpnd3BjcDFW\nU0pTRHRJY09IbDJCVkQrODJWa1BZTno0TUw1TUNnYXRidGFTKzFhY1ExRDBm\nL25BU25FNW1VYnFiQm50OFFBKzR6RUNuSHJuVU5DSzdqOU51dktyYWx1TXVM\naWhjSWxTVWRCaEtjS2dZWERPSENkaW82Nndna2ZKOHpGWEQvNWlFNlpoQzhE\nTFhqdnJ6T3B4Q08zMXlKZkdRcS9XWDN2S2dGTHFpM1E3dmZqM0xTUDVOaGlY\nWkg2T2g1eElwelFMeHo2cVJIV2NGbW83cThvcXN6TFlRZE9Xd3RFSnVTdVIz\nSVppUzlJZy80dEpnZ1ZZdjdOMGVMRXlDNlN4Y0hNUkdQQ2RzR2FBMFA1YkFl\nSGVoQW80bmd3b0t3dDJqRlJwbmd1Z1V3bzVDQUI5dzZRZ29oZklMckRsY2t5\nUGZudmVEVlJxOHVyWFRJa3RMNkJlNm96VlFRZjVtQVZtMG0wR3ZwcVhkVFJF\ndHBKcW5SeFlpTTBHYWx4aEJWbGZNb2NncWNnTWVlZWFPdUhYdWQ0aTZFUkx3\ncFJ6SkNEYXMwWEk3K2Z3R0lEZENDb21uT254cUxnT05GbGJUQmpvSG1iM3Nn\najlTMmhHNzJjdzlFWWFOd1FrR1VrNVJtaG1kbFhIeWNEYWpIVWd3UVhlK0JF\nVTd0cHBvd3hEMUcwdXMwVG1wQTdrOHBFS3g5b2Evb3k1MFV6WTV1cTl1OXU1\nZlhqdWRaVkcyRG9sdmdOUTM0aXNTdU5LOTMzYkt3WXouTWdwT01nZTFsdWRJ\nbTZ1Mi41VXBDZ1lMNVJMWTRESjUyMnpmWWxRPT0iLCJzaWciOiJEK3h1czhp\nczZHbXI1ZzFVbjVwU1BSTUtpTGpqU2I5NGszbjM1QmpOWTQxNHo3SDFEeUZx\nYkVlQ2hhWExoajVqTEg2WG5PR0pFSDFYaXNNWUFMdjhCQT09IiwiYWxnIjoi\nYWVzLTI1Ni1nY20rZWQyNTUxOSJ9\n-----END LICENSE FILE-----\n"}

	err := lic.Verify()
	switch {
	case err == ErrLicenseFileNotGenuine:
		t.Fatalf("License file is not genuine: err=%v", err)
	case err != nil:
		t.Fatalf("License file verification failed: err=%v", err)
	}

	dataset, err := lic.Decrypt(LicenseKey)
	switch {
	case err == ErrLicenseFileExpired:
		// noop
	case err != nil:
		t.Fatalf("License file decryption failed: err=%v", err)
	}

	t.Logf("dataset=%+v\n", dataset)
}

func TestMachineFile(t *testing.T) {
	lic := &MachineFile{Certificate: "-----BEGIN MACHINE FILE-----\neyJlbmMiOiI0dFpUc2xpb3gxSUlyMlp2U1BjdWpnSmZUV0RadWdpU3ZaVDUy\nL2FTbS8vYlBHeUJTbTFockc5NWNRejRIbCt2b2lodzEzNk9ZaTRuUlhmQWEv\nS3pNMktXcm1tMHdaMWx6eG92QXErNkV6dUFnb3haT1VtZlJqVmx0ZGp1aXhr\nb2V3T0NvMjRRMFFtUU5uaC9EZDgzSnBYb3BOMnU1MEdqbE85RFFxQi9pM2pM\nLzE4Y2JUL01LdlQ3MlRxejkwcWM2aDVTY2k2TWRmUkhpZlcrVDQ5N01pZ1pU\nQ2dkMjNPTitBWVBDY2V3b2cyU0RqaENFWXhiKzFGaGc5Z3p5VmxXVFpNRTBl\ndUtHZ2R6dzVTeW5WQVNqbnlSK1kwVUFBc1UvVnRGd1dDV3RkRnIvblUxVnFs\nQlgwSVphQk9uS0hYMmNpRWt0NGF3aDAraElETmVzajVMR2ZTTUsrYTJNeGFi\nQ0w3cndWTVNNZTBsWGdlRHppR29jTUVHRjJJcGZKM3VIdEVTQW4wNlRHN0dR\nN0NlR0RocmhDTGdNZk1RUlhiNWVjWks4d25MNTk4MVJwc0hqWnFDSWVZNUdu\ndXBPWlFBWFI2VXVIVnh0YU5WNEhRNzZyYzdDcHpDaEZiSnBCSDFQTjNkZCtz\ndHgxYUk0M2NVZ29sRU1kTmprOEI2VndrT2ZhUFdqUC9XVVhQeG9US2J2Q3d6\nZ1c3end3c280czIzU25lQ1JhRkdZdmN1RU9RSC9UVnJEc2k5T0FWZ2RBTTRa\nYkRRM1RpbHM3cXJrV25BbE9vTzVOK2NmRUI4R3AzTUFrRHV2QW1nbE1WSE9x\nak5aYVFaRHcrbDJZL1d4VmtHTk5LalRBWlduYmlwMG54ZURDc0RqZEltU3Fr\nVm05NmhGbElBWEpQRWRUbmgvMmFXV0g4RXZnS0RyYmNKcWJIYUNqMjJHT2ls\naXR3SjRPWWl2OFAxUktUUDZCTlhZdW5QaGZuUEdQdS96bXVDRFFsbXV6anlk\nNlBiZG50c1RMNjJwaWtMLytUNUZBUTgxblpXRDRrSk1RNDZ0b0tDaHRSSVBs\nc2dmZVJmOEdZSm5Ta096S0E0VUwvbitFbEVNckdzR2xRaFFSMDJYbjk2clh3\nQUp0bjVFOUQ0YStUbUdRZ0NGQzRHOFBCN1EvL2czV1h4RVQ2QWZwV2hOdDNx\nTURBTG8ydDRzdmdWQW91KzlyRUpUMUtoTHVOV1hWNG93YnNrSFVCditBenpq\nYlJmYm5RbzFkckFvUmpqNk9XQmJkQlBFQ2M0T2VDMlpVUE8wUDI1aEJtbmlQ\neGZqUHJVaHZsS1B1dFRTTWJMUkl0Q2N2WTZlY2lXMUJ2WlZwbUl6Rm1KQTY0\neHFENjdaaVpKTGVMamhUQUJ2c1NxKzhZZGtxWUo5RFZHOHZCMnZCOTQvSUJ4\nT1NjV0FRdXE5TjAxS2R3Zi8rc3lTKzk3aTFyNjJ1dmcrK3ZxZk9NS2dQYkZV\nMndhRnExYVNlb3lrNEdENEZIZC9DYTBaV0xZc2dLamRiK3M4Q2JBZjlEeFBt\nUjBNd00wNit4cUpOTnJtbDFQV2ZyVWtObGZ6TEg1S1Y2UDQ4MU9BMXNJeTFW\ndVE3WE5MdUJhWEVPZEJpd3Jpa2VwVVlNQ1RkTUdObytldzkwQ0MzQVF4WTlU\nNkRtYXJSYktad0w1NFdhUE1iOXNKOG9UaC8zand3dmZqUUVlWGFabWp4U1lw\ncGJzWjhYc0dxNDVWS2xGNE5rSGsyS1Z4ZW5BakZtMXo1Sm1vTTFsY0hJSjlj\nOEZWMEZ4TkVuZGRFTnN2THpwTitmRHIyWURrVDNrNDNWNVd0OU1RRit4SnhN\nbHZ5bG1hR3Z6eFAwUjVOV3VoMGFoSVRYWUV5bG5YTldSbTNCQ2cvVG9QVzhw\nK2hpMU1oNXM3cXI4Y1k1TXRBQWRoYzB2WGljZ3hVVTFreHBNVmp6elp3dGcz\ndWJlQkN5YlNjck5KcVR4QW45ODJSVHBLdFpaV3l0Z3RtalNwczltOWpZV2ZM\nWWxwYUtJVUxwcldWVVdvSi9SdUlQWXlmWU5LQ0Jsd2VCc3NRUzFNYzdZQkxL\nU2tNK2E5elJTVzIvcWxJaFNoSExTU2srOHZ1eDNTOGsrdHpLQlY2c25lRG9S\nQ1BnblEyV283WlJLTHE0a0ZpdVFDTmhWNG5XV1RLUUZGRTNjdFgydTdvMHhr\nUWFCRUxQQW5ieWYzUkwySTNrN2sxRHpXRlcvRzlZd3RvNVRlSUJjaHdzWVBt\nS1dkTnltNmtZZXZsbUZMUmtzKzV0RzRsaW9WZVhtc0dRTmFoU3piWktMVSsv\nRWhWTDZhcjdoNkpHNlB2RWJtVVhnSmNpUUtPT2hKRFNQZ2tSWnRGalJKVU1S\nRHZlOG41MjVzK05oZEVtSTZSbHFRMVg3R1FLY1krMzIzdHVlZzd5MlJ4VDBM\ndnlzWVN0ekFPOHhwTThTVVdiMEk3dU8zRUwxU0R3YUJGK3V4RmNzcGRML2JG\nT3lKdVVkaGxOaVBZRXNWYlhRT0J5NTcwVC9wQ3BiYTlmdnRyRmdsWmIwc2hD\nZ1RCQ3k2WmJibWJ6T2hleTdQUHBFekhVLzJyVFkza3VuNGpaMDRMc0JPK1Nx\nMDdHYjZwM0d0eFR1d2N5cC9COFRobXJrVHVibVZoV2cxVHd0eWFsSnRxRWQ2\ncEx6bmU5cVRMYUQzdzYzSlpXUXdBNTR3VXFFNUtYZEZuTVVxdGJoTUVOb2Rp\nbHN3OWVpaUgzMGd2c0YrSE1FcG1zU1o4QytJRGdGUkJMVlRPZXdubWROUlVp\nL2RXRVNGdHRRQzY3L1BBSFRwc2FqTCtqeFlBOFk5eWpSc0VFUDNTQWxoU3RP\nSVg2Z2V4MTc4SkVUOE5YRWxvNWt6LzJ1NVl1UlZLM0V6MkIwRjJHR3dvTW9h\ndnNJRDF0SUNwbVZQcXhZZU9DTmlGQVlDQkFSVXNOY2dqODRMWC90TzViNGty\nYW81NTBuMDBHbWZlQ3BNUVc5RGNPSVRucXUvWWRjQ3JTUmYycEx1WklBUmZ1\nUlRUY1luSlAyYURmYkg2Qm1USzBOVXhYd1NVT1JJSzNTTERVNmlyd2RLM3dw\nbjZhNTl2dHpKTThRaDFwRGlYYnQ5dmdsVURHakFVQVpFOXRqVmxncFJzNC9w\nRGhYdlBaZVhYc244UGdkUXhFVElMK3NhUEFqOHRqVFZtalhISjRZQzFXSXBO\nL1ZYdHoyR0UvQlUzTDFyQUdocVBhM0lkL29Uc1VLQ1JtMkd3ZCtzeXA3cDRo\nKzBiU3JZSCtua2piQW9ObWJRS2R5KzlLVnhvbjdUcUszdlZ3a29CbzhzK2lW\nMEIwUGxaOHlXUi9HY1ZUS3dUdStzS2E5R0ZyUkp6RHNUVmVOYVF0Ym1SaERW\nTDlkS1JHZUk1UXBJWUdmSXhseHJyd3lvNytuY0FwS05LUnJmMUtQVG5MYWh3\nR2RPaE05OEFncmNKQlUrWkVKc0swaE5RdW8xVWROMXVkTXlITlB1Tm4xenRV\nb1lJVkZuZVM1b2R5OS9zQ1RDOG5kdE1SSTh5cVE1RkZpbVZEUW5KUXlrRTR6\nZ0lMQ1pMc3k0SUN2OElja0tDLzhmZU9kaHBRbkZDcmFSSFpPMEdCY0NJVkhR\nWTJ2bUxGL1pGVUdFSlIxMy9nckpGc2ZtWVFITjFkQ0dLTkY2YllQZ0tHdFlz\nUDJWOTVYZjk1NjVHL05aSmdnMmZhZnhpclRRRk1pZzAwOWRVQXpzZFhGSFB3\nVFB5Vk1aZGthSkhBaUxkS0pFN2hWRmwvVUJjaUU3dXJWT280SWFmeXE0T3hk\nZmpLVUJsMmtJTTBQNHRueWxUM0l5WkRwYlkxMWNOdkp3ZWVyMFpTN0pYOE10\neUZmb0xuK2IvcjVnR2JpcFo1bEZDODdZVlhtK0JmN1lCY2QyZjRYbnAvRmM5\nMEZHaVRCTXZQbkV1U2QyODdXWllqMEZ6eElCaEpieUc3cE1BSVVCdEtqQkhs\nV1VYcDltQWJhVDFhTlBXSkhnakVNWGdxZjMwaGF3YVJhOTBMSFlpNC9ScXFB\nUGs3cElkT1RiUm4xL042eEFnM0FvYzIwUGVTSWlpU3FSc3pqTzBwSTlaZUdH\nWXk5OFBNWVl2U0EzTE5KV0lJaFdjM2xmSWxtTEIwS1VDUjBqcHE4N3lCaXlC\nb2tQSlBsWmlna3Z5VktwNEdZT1NQby9yRVJTUVBENFNQS1lwaTBLaWxWSmVS\nWHlxYnd3V0k5UzVIT0d0UThyUXMydVB3NHdQanBvQk5wVVVlK3N0SExsUm0z\nSm13TVZrZlhDcTJ6UGFSdit0UnlrRGY3YXJXMHAyYnE1Z2gzdEw5UkkxcjJ0\nZThoRmZTN3ozWGxpdHFudjhGbDJpVUU0L293RkpVM0hFYUgrTXFISzFObWNz\nRVR4cmFJNFE3a1hjaTh1aWViRmhWM283S2JETnNlMk5yVTNKMzZKb1lyUG1Z\nWWFHeUo3M1ZTdjhHSHhoTDVoNWpxRjhDM0U0eHgzUVR0TWliVG1yVkF2MnUr\nMTBWRzEyd3Vpc2NKUGNIbThoTCtGNkxnYW94WUE2WHF2T3QvaHZ1aVh2MEpn\nTk5IakF3eUtpZ2pxNHRPNTlCbGwzOExCR2hzRHQwLzYzaExXYXBPbGY3UnAy\nWFAvblArYURqVHBaQjFiOExCb0dxUE5Na25aUmVsZ0p6ODA0S0hTQUhvaUZL\nbU9EUGJEaWdKR0puL2RjeHRiK29MdWVTYzNrVHBJamNqaUV3LzlLRytuaWFr\neGwvMzI5azBkemZ0c3JCa1hoVjVTbThMMzdwQUVQYXdvRFo0azZsVld4WXA2\nRFNLc3hDQXQxbVpYakFzY1lmeEwwSXFkR25reCs2aStPakJYY3h4ZzMzaVd2\ndWZjTTJ1TW4xZHM5Q0Z4S3M0MU9rVERiUzJFOElZUi9YUVlDS1VZeW9aY2FK\nT1UxUHhPTjByZEl5M0Z1SmQxYVY4cEFxY2FRaW82b0EremtJR0FkbUp3dTFx\nTFVZNFNYMmNhZGttNlFFNk5zWnM4enZZNUZabTdOL1dZMjk1RzVQSEJFS1JD\nRHdMM0pGQXE4UHNlU0I2S1R0eU9QeXIyM2FhOHlMcitjOGdLTmdxRnQzdzlD\nMmgrSXFYZ2tiangvY2oySFB1OWV2QXc0NjZOMkpidDhTVXNRRUszMWc0eGs5\nUEpvYmlyaUNLdmFQTVJJaFdFRHdXUFpNd2E1TkF0dENoTFRvVHZOVWZvOC9w\nRXJlSUx5NFZ0Z1ZCMGZLMUxrYlBCYjVnTTgxaDR2SXFUdHhtOUNsajlndGhw\nV2U5dHAzbDVGTkNVM2Z3Q0pyVDRBcDFjOHE0Y0d3MEZMQ2RiNFcxb1g0ajNo\nblYvS2FoSGFXeXVyVlJVSW40RjRXY3dWTTQzTnFoTmg2azh4MTNTNUh5aHNF\ncWdUYzRqaFN4Q1IzS0g4a3Yxb0VRU2xnWGI3cU1vaUlUQVFmNGZwempSRkxo\nS2o1UE5WMWcyL083Rk9qY1JLWTZNajU1WDVHc3VRZWJGWkFXd0ZuMy9LSWlu\nemZJUEUrRnBSTEswVXNMbHkrMWRhcTBnd3B3QUFQLzh1Q2JuSHVFTG1ZRzhE\nUnVBeDRVRzdmYjJ1NVZ3RGV4RDZaTTR4T1NWaW5kYmhIN2g4bnQ0VUE0ZVhM\nWlh4SHZIQW4vU3JVazRZYnJKc1FnRlV3Z3ZaV1BUVFNZY0REeitFd1VZeVVU\nV0c3ckhMMnlBUDA4VzRRQ3ZoZTRIdGM3eEwxTHdWcWRVb0F4TmtUbmQ1OWZt\ncWpIS0VnSVlOOGhMSVlmano5dG8xbm94aDBlbkpSaW11OGJlVWFpRnVIOEhu\naCt1TXJTNEhYTS9HR0VXektiVjVRZEhLRDl0a1BBbnlTWW8wWVArdkpwQS9E\neU5CbmkrNUNHd05kWElpVEZIcEs4QlE4MGtRdVE2UXNWZktDNkRYNjhrdTdr\nL0dwQUtxSHBNYXNxeDBIZmRiTlVPZEZYM2hxK3pLc0tTNDg0NURBUVhSMFNO\nQmF2VlR5WG0vcjBKajQvNUMrT3FESjNFWlhJd0JDUVdSMEJSdW5YZ1ZOT2JS\nLzdVd2h5bnVIZDZYUHAwWjJDZ3V2aVB5NS9vanM1dG1hSm5pSzQzVlUvaVpR\nZytqMHRFeU5USGYwRkVmRDVtVVBRTUllTUlvTkM0U2xRMjRRSmxhWGRHY0JE\nTGUxelh3QTZBY0NHcFBGRFd0REJ3MTVueXBoNDRXK251ZmxvRExvSnovMmJ3\nNnl3ZDBUMlRpZllTUFEwQ3R0dG9aSm9LTm4xWExPVFFPSmJSa0duQzhiQWFj\nakVoWUx4MXNxUXZHdWZTUGRERE9HYithOFJ5MFFLMjN5Y3BUMFVsYXB4bnVi\nQ2RVMmgzSnBRL3NPL2FPUW9tYlREZkVod2QrKytreVNmMGxBU3ZNY0xhd29F\neGhwb3NXNTFua2NYZEFOVm5uSTZzMXRTUzM4NzhLc2h3bjZXSExORXBxNno2\ncytCZTdsNzgrMXBxbHh6OVYraURLKzRPa05yQUFiM2JzNTE5TnU1bnJxODMy\nRmRGS1NCTWFKRUgwa2NCOEVuRjlROHZidVd1SDZuSVhrSVpFUXkrVjVFU2Rm\nNWkwcHBYUGNaTGE0SDQ4dm5TWDdOcU9UbFBqOTlYSmtvOW1QWSs1VVFXYzc2\nNUZZRS8xRFMyM2xmWEpzYWVvRWpBTUNxV0loNlVNR3JaK2dsRmdJVDRSRTRZ\nR3RRd0VOeUk1LzRTbGJ3bG1zdlRsUHBRWmVaVHVSenpEaVhLQ2d2cHNJRFhy\nYXNBWTlRYyt1UkgzNzJING1aMVB1bUZIYk5LZmdUUTA1c2VYbGUxRXlROU4z\ndmRQL1JPYjlYeUNYeExCa0J1ZTRRUENaU1RjVGVyWEpTNGhNSnVGb2lDZUcr\nMm9YeHozaEloRmRKV1hpRFo1NWtqSU45SWo2YndZRFlnRytQNkdiWk9tVDRV\naFJDT1ovcHZocUx2aFJ4TkVvazlkcmduaEFrMkkwWVZBbjd0NlRBaEdCVnFj\nNW83aFo1TkcvaWJEVDFxVXNUY3B4T245Q2ZoK2lZb2E2NU9GVDZGM2xQR0tL\najJQWjhjdk1YdzN3cXVITmdLcE5IM1BzMitlbjk4RFIzd1VWOGNnenZnNG9S\ncGVMK1J2eXR1YWdEV0phWTFXYW9TWEh2S3VNT1NKMHNBWjFSQUVEYTllemMz\neUlPc2RkcGdqdGlhb0RFekRGd2U2cGJQbzJRblAwWU5adHVXYTlVT2MvbVho\ndlJtcE5wSXRXZzR2dmFCNjJ6SjNrcDZhWkY5YndrVkcvV3hGSC9pWWpiZlZl\nalNEVlNYUnltdk0zWXQzKzNDV3BlcWwvWU0raEJ0enhkR1lndGhNK0JBYVFJ\ncXFJSCtFbjlVcWtuMHMwN25ueWxDcjJKWkkwa3EyN2pqbGJOeWlFV2gzQWZO\nbkhsQUhmanpRck9OcU5zdklEald5WDB4QmQ1TG9UbE5EajRqdHo2VDhsVGUr\ndWxDWDRocjZSdTVkcEVYUFI3aDBmc2I5c3plWW1HcDNXMU4xS21VRmtsaDhU\ncTVWODJDUU5aRUxNQUlrOWQrRWNTSDlaWTRjNStRc2hiblA2TkxGd2ZNcUNM\nYlZZcy9lVlRGNCtqMnpicy9PSjNZUEpHeGQzVGV5R29rSWVPQVJGaS91L0xo\ndmJidVVJeXhQZnpacVZhRWptdDdnUmNaK0lLQnAyWWZhRnVsb3MwbHpQU2lK\nSHgrMXRDWGFqdndlOHVzTDlBd3hPOENkdW1Vc1VpNUQ3cEg1UWRPM0h1bmgx\nV3p4YTY3cGYvcUY0NVJ0Zklqc2NKdm1aRVp0SDA5ajdjZnpTeW5vQklBK3lx\nd1p6a2pTL2RNUlgzL1F1M1RURzNxaE5UdCtSTkp2WGxURXAyNzN0Mi9GKzNF\nYVpNOGhHcDJlTVFOdGpFWWlJVlljTHl1TFJjbHFrazRZZWNRa29IY0NSRURY\nZE9nZGwxVHA3eUZ1bVY5RHcrcEJ6TmdBaDU5R0U0WktNM1pqaE9IMG0vUTJa\nZlY1UVpDdk1kVlVET0I5aDJwdmtGNG92OVZzcEJQWTJOdEp2ZG9aT1dpbkV6\nZElsdXVLZkJ2MXJyWGI3UzBQZmhmdklHcmVQdmNqTndiaEFrZDNvTmZ4cU1S\nYm8zNThDZHJrQW54Ym8wNDlpTDJRN1BLdVQzbkhrMEVUS3JRZWRzL05tSFVF\ndXNQb2tqTkNGY0JuRmNuZEwrZ2tzTWxuZytjT0lnQnBPbjdsS1pZYVVweUF1\nUWZYSlB2SDFycjBCTHVHSVd4cTFrMUI2VDQyWmJqbGdtM2o0K1RYTWRSSFVv\nSWRmZmhrMU5KbkEwakduWEZ2RFM0dlduVFNDOGVxN3B4cTJlTGFCdXZIZ0c1\nT2JPbzJnSWVMSThDU2I4OGE5ZUR4Z1pvZGY2bHlCZ0dxYmFVYWdVWFlTSGsy\nMVlXY2lPeW0rQXRVQktxWTVjM1lkaWMwcnEwKzA4dTE1YzdvVElSNmVKYVlw\nOXNXeUNlSktsdHZrbGc2NmJMblBqT1QyTWMray9oZmh3ekF2UXJLZ2hOQT09\nLkhFYmswd2JnN2o1b3FpVUgucCtvWVZGR3FWL0oyd1ZCMzljeEcxQT09Iiwi\nc2lnIjoiTE5NVlBtNU5tK05rRXZISnRaMm5NRWlQTDZDaW5Ud0lYSWtJbGsx\nREZLZU5SR2hXcDBmc094MzAwdDAvYkpIeFcrMm1FSGU0UnFTMnpBV0Jhc2Vo\nQ1E9PSIsImFsZyI6ImFlcy0yNTYtZ2NtK2VkMjU1MTkifQ==\n-----END MACHINE FILE-----\n"}

	err := lic.Verify()
	switch {
	case err == ErrMachineFileNotGenuine:
		t.Fatalf("Machine file is not genuine: err=%v", err)
	case err != nil:
		t.Fatalf("Machine file verification failed: err=%v", err)
	}

	dataset, err := lic.Decrypt(LicenseKey + "39bb2cae-af5a-40c2-80f7-9e2ea0f90d17")
	switch {
	case err == ErrMachineFileExpired:
		// noop
	case err != nil:
		t.Fatalf("Machine file decryption failed: err=%v", err)
	}

	t.Logf("dataset=%+v", dataset)
}

func TestLicenseFileNoTTL(t *testing.T) {
	lic := &LicenseFile{Certificate: "-----BEGIN LICENSE FILE-----\neyJlbmMiOiJBTy9VZVBRMzJwbTlSeU43bzdWeEI4UlRhRmJPTVl2aWNTMzBY\neUkwQ1FwMloyRTRkRW9rd1g2c3RDZ0xyNUhaZElCUjVDTGx0REk4QjRuK2tE\nSDd4QjAwM2pTWVAvTTRoK0tmTTJNSFZEclZWVklJRm8xY0Nrb29wYWZCUVBw\nWDg4UTRrWWNLYWNua0E2MDRkRDl1L2YzWEh2MUZDZGdRYWxGOFhpZnV4QTE4\neVdXSCtTTlVPNVZZRDRqNDhKaDN4MS81TUtWN3pyNGJqd3Jubk85NGhZaUd4\nZ3c0VWYyM3dMUEZwTTBOaU9jLzRpZ0FPT2ZQOWU2bUVFSTgxa0hOTTlBellD\nOUJlbjJmdkZ1YlN6UTl6UWhjUDJwdWtaNWR6L2kwVTd0VGpCUWYwMXJabENl\nYzdYb05sQ0s2MXp5cms4eVI5blhkMXZZWWgzdWpSU0V4V25LM0NYcllrOHQ1\nREg0ei85TnYxSENWR2dha0RFU2pIN2wrSUQ0b0o0NTFOMThjVUd4S1hSTldT\nVytWdi93WHZnZUFTSEJCRWhScVVEM3d3cWZleGhNRnBsZkJsMTkxeTBKdWxm\nK1NxRy8xWk4vVXhjdEJDdUlac2duU2dkMjdhOU5ubVNHenk2ZUJSOWhPZWo2\nVmhva205KzYzWExVeVBIa0Y0S1NKUGRqcVFrdUlVSFh1bTR2Z3JFZnVWNVJu\nZDZlTkRVYkpDSUhOWmM4bGJCRjdERHpLWjQ0VFdwTkhlZVlYRjJCR2JNeTJZ\nZEN6UnlJQWlONDRmK2g2b1ZPQTJ5cHliSHhBRkRTcGtLWEgzOEt3K0tsNTIx\nczd2S05pUVFqM1BFS3l0clJzdzFGRWoySXd5TGlZbWZzdGFHM3JiUkUydjhr\nWjloSTZkYWpEN2I5M2ZtaytMNjEvaGV4VDhzRzg2VDU2N2pMRStkS04zdWQz\nMysxMXJBT2wvVG9vV2tPNWVaM3ZNeW1SeG9raEhhR01BV2VhWFBKN1ZqM1pI\nTElVcUsvM2VOV3JPZUtPTytyL2gvWGxjRTBDOFFUcnZxS2hWMFJWeWZLc1RD\ndGdreGpEREMycXc0akJGblFsZHpRZjlLSkJXNVNrOWQ3MWhkU0RpZVowdysw\nZlNIN1c0ODBpNjVFa2pNTFloN1c5TzIxRDRDUzV3QkF0d3R3TXRFY2NoeVNv\nUWdyWjNZZHZmM2RIem4zSzlJVjBUL1VsQUcwVUFOZk51S1JSWFVWZGlaend1\nUm1mYndHU3Y5cEpHcWZSYk04TWcweGswRUJlU2UwRFhvN1NsY3VLMStCVFlC\ncE9aMVE3R05ma2FYaUh4L2dlRUx0Z2k1RVVNZ3p4U2VNYThhc1JwUGxnaWNt\ncFh3UDZNSHVmMzVhUDg4VlJVVGpXazR6Z1VLa2w0MVJaMVBRV0d1OG5lWktN\nMkwvQmtEVDRHZWF4U1UvVkNOckxHbTBxeEk4YnZ6Z0RiWTFBdXNta1oxelBk\nUGFRbDdSekZWbzV4TWQrZXNWcUdFVVJEUmpxVVlPWEY4MGFrYjNac3NaSmF6\neFJla203VjNoczNsTEFsbkZzcnFvY0dtM2tQZTFMSzRsYThBZFNzUTdoQyto\ndDgvbDdUUkVjZThmUjFDSmU4N09nNmpZTGZ6anpiZkRxaWM0MXBFZXRDOVJk\ncHN6VFkxaVlGbTM1bFh5TmxMaU95M0dBSHVBV2lpTWxtZWtwYnQyTFYyek9D\namEvRHorZ0g1K1QwV0hlR3dSSmI4bnRjeEdIUURHbW1kZnR6bFEwRkpQWUR5\nZHVYQTB6T3M1a3FzQ1dCNUwyRlJNWW1YeGZMOGFYbkZxNW4ybWlGQXhxZ0pZ\nZk5CMjZvZ211T05Bbkk0ZkNULzJab2l6K0RBbFNkWXR0MW9GR21kRVdmZG5M\neUlhczhGTGVmcTB2N3Q2bEpMcFZNUkM5SXIxcUs2K1cvTksyeHhGZEVnMjha\nbDlDeG1xVXMzUDRZMjh0ZnVVTW1Gcmo2aHA4UWNwODlUM0d2VDBEQ3ZRRCt4\ndzBuNDM2N3RqM1g0emZ4RXloVEwwRUtuQ01zS0VoT2V0T2xoWHdSNXJseGQ3\nc3J3aG1ya2Z0WHRjendwMmM2aUNTTk9mR3V3RTRmZnJ3TnBmdGxFbWJlY0V6\nTGVXeFFjbFhEMlhBMVFJcXcwOTdzQ1hQNWd3SE1DNlh4azhCTGFKSUpGZkZq\naXVVMnM1SzN6UGIzZGV4cVdCcGRLN09ud3pLcXNKNFBjOHVZVG14cXlCYVBR\naTFTVGgwVmVuSG42emtWTkQvejdxSElCakYwd1pmcTZWUUkvdkVUWTduSXNB\nM2E3UjYvcU9XOFRiNG41V3RFd1doWWhFVlZPalFEY2haZzNkSEl1MDlLSk1z\nV0RIV1EzMUJoT2xBMDRYd1hRUkxZMWlzZHVWVjNMbGVJNlBLR2hSWlAweHg4\nejdud296SEZaeTNuOEU5Q2tQN0FGbUt6SDBXblhySnpnQ1h1MlJJeVZtbkZC\nU1hLVnBLOFkveVNpZHNTMHlsamZSSE9OTEZDT2hiQmtFcHdIc1h2ZEFVaFoy\nWHNDM2JOL0piRWpVMHpSNjJKZllpQXNjTHlwRjVlYUU1STUzV2FtWUpyU0Fz\nVTRybkF5cVN0UEt5Y0YvNExNbkUwRXkrWWh3RHFGaUQ5cUN5dzNscGswTk9T\nNkgxK2VhSDYwbytlY3RESHBzb0Q0ZFhDSkVZT0o3NGh4MTJLcG5XNUwzaHlq\nVDlmakxHb2lYQmJHWFA1MGVVTjNiaEk0alVyZHVMQTgwdDJjcENuT2hWcG9R\nMjZkZ1VhVmFqU3IxYjVHWEt6YndVMTBqMnYzRFdSaTFGdlFZWWprb0JJUW9z\nRlJYc1RpWitmMnk5ZG1LZStmZlRaYXpuV0d5eGFEQWVTa2R4WTJwdDU3RFNs\nOUx4dXpoVVk2eUlZQzBpSjkxeWZKaHRtaHNwdG0raktWVnNqbXcvakFlZkNG\nOUVrTjN6SFpZQ3l5cHlVLzg5cDZEU3BsNWd0d2NpL3hEdG93N2RNdFNtTll4\nVGdmengzWWdiMFMxVWZFdWdXOTVZeHFrUHdCamg3SFk4bTNTeDRQYkJ2S3RQ\nbm0vNkE2MTM5blVMNE4wVm0yRmNmZDhhVzl4LzQ4azBMeWxJMkdyTFRFMDhm\ncnBNMlp4dFlyRURENUI5ZXdRTFZUNDhJRUdnSk1KNnMrOUFncHdKYTZYOTBw\nUEdPRGpPN2RDcWEvaE1RTTZGYWtQaHVBbWhGS09acS9JZlg1Ym9FZDRDcWRx\nN1VpYzNtYWxNNTFkeEtuNGNTT0I3UXdyY0dsSkRxWXFPVmUxWDJURmlOU0R0\nOWwvTGlxeUpGZitKUVdHMHd3MTJYTFpwSjBzbkkyWEp6UG9hekQ0VU83Qm5V\nOVZCbStTbThTTUxzQUtFZzJQYkVXRGVHT0dYcHZVTFNRNHJzUElKZE40bFM3\nNmU5b1o4NUtzVTFCSDQveGJUTGdSeVZwSTB6QXFYTGdISjJpNFM0QnpicnRp\nTTUvK3pMV0tQaUl2MmRjQlJSb2YxNFM3UjNKOFp5ck4wdmxOcE9hWFZoVG9B\nTkJObEk5dWovTlNQYlhkMDV3WDVSdklmWGdYMFNUZ0NncFdseWhTUnhIS2Zs\ncmdFOThteXp4L1RpeGlaWFV1VUZUYy9La2NYQTJwOThlRytYTUxOK2FmZ25K\nM3pYNHYrclJjamdEYy9RNUdlNlIxdWJIS2VwRC9qZUVleGdwdzJBSTg1eDRB\ncGR2R0NlYTU0bUwzQVRidjE4UmdiK3cyQXV6b0xidjBZdlpVZCtxY1I3U2JQ\nZVBtd1V2aytnbkRzYWk5RXRzZnRPdkdUU2prdXhULzkxOEJvd3N0ajc5NkVJ\naHJaaG50TGtsUXNTcW9PbmkyR3dUVnpJcHhYQVU0YVgrZlpVZmdDU2kweFJQ\nRmJWdG54WTNpOVpCVVlVQTR3NXArTnI2Ti91TDF1NEdjbHRxM0RBNFF6TFpu\nNkRSdG0wREdVU3lIdzJ3Z0d3SHNrTGRxVjE0cDZ4N3VpYjFXU2tIcHJ1bXdH\nWTZQZGxpaVhtbllRV3Y5UEVraFIrb1M0VVZJZDRZTzdqODUya2Z1czVPTFRx\ndXhFazFIWWxQd2R0SCtuMlI4eG9uU3lNbTByVmlHNVh1QUNLK0RYM0pPZFMz\nOEQyOXcvR1dIckxHcDdQdUpEcmNpenR3QTYzSVhBWGdyYUZxaGl4YldJTjNu\nVUxQeWJLOENUbFhZWXo1bGR4UlpQMHdQR1pwK0d3dlBFNThCZWZ3YVM5cXRw\naXpvT0xZMkxZVitZalRxYlhKQ0J5aDJUYWJ3ekJwdUtHTjlMNk1CRys4SHlL\nTmltNFMvaUVZcHR1L2VmV1pmajR2TnM0RFRUMFZDSVg4UzQrR0xtWWNiS1o0\nWGpSOG0zd2xEWWVDWWZ2Sm52b3cxcFZnZXc3SVpiLzdvQXFKY1BSMnVXYkZu\nTXdrS3ltamJhVDVQOVJOWmNDeDJ6THJqdlBqT3dMZitVSXBpZENOK0tJQ3hy\nSy9yZHFlcFZQN0ZpdmJzOTJ3aUQ4TkM5UmhtQXpCZzdTQT09LmJndnE2Uy9h\nb094SzFwTlMuYmdVcTEwcEI5Ti9EbUcvZExrNU1VQT09Iiwic2lnIjoiOFEw\nTmV3b0JzaTNlMlpBR3RQaG9mVFBIT0JZVUFOWHlYVEU0UHFpSzhCU0FWWUdB\nUUFNdkM1bXhNLzBLeXR3a1NSekRsR01NWVRERzBITXhYbEpvQlE9PSIsImFs\nZyI6ImFlcy0yNTYtZ2NtK2VkMjU1MTkifQ==\n-----END LICENSE FILE-----\n"}

	err := lic.Verify()
	switch {
	case err == ErrLicenseFileNotGenuine:
		t.Fatalf("License file is not genuine: err=%v", err)
	case err != nil:
		t.Fatalf("License file verification failed: err=%v", err)
	}

	dataset, err := lic.Decrypt(LicenseKey)
	switch {
	case err == ErrLicenseFileExpired:
		t.Fatalf("License file should not be expired: err=%v", err)
	case err != nil:
		t.Fatalf("License file decryption failed: err=%v", err)
	}

	t.Logf("dataset=%+v", dataset)
}

func TestSignedKey(t *testing.T) {
	license := &License{Scheme: SchemeCodeEd25519, Key: LicenseKey}
	dataset, err := license.Verify()
	switch {
	case err == ErrLicenseKeyNotGenuine:
		t.Fatalf("License key is not genuine: err=%v", err)
	case err != nil:
		t.Fatalf("License key verification failed: err=%v", err)
	}

	t.Logf("dataset=%s", dataset)
}

func TestUpgrade(t *testing.T) {
	opts := UpgradeOptions{
		PublicKey:      os.Getenv("PERSONAL_PUBLIC_KEY"),
		Filename:       `test_{{.platform}}_{{.arch}}{{if .ext}}.{{.ext}}{{end}}`,
		CurrentVersion: "1.0.0",
		Channel:        "stable",
	}

	upgrade, err := Upgrade(opts)
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

	// Latest version
	opts.CurrentVersion = "1.0.1"

	_, err = Upgrade(opts)
	if err != ErrUpgradeNotAvailable {
		t.Fatalf("Should not have an upgrade available: err=%v", err)
	}

	// Future version
	opts.CurrentVersion = "2.0.0"

	_, err = Upgrade(opts)
	if err != ErrUpgradeNotAvailable {
		t.Fatalf("Should not have an upgrade available: err=%v", err)
	}

	// Invalid version
	opts.CurrentVersion = "<not set>"

	_, err = Upgrade(opts)
	if err != ErrUpgradeNotAvailable {
		t.Fatalf("Should not have an upgrade available: err=%v", err)
	}

	// Invalid product
	opts.CurrentVersion = "1.0.0"
	opts.Product = uuid.NewString()

	_, err = Upgrade(opts)
	if err != ErrUpgradeNotAvailable {
		t.Fatalf("Should not have an upgrade available: err=%v", err)
	}

	t.Logf("upgrade=%v", upgrade)
}

func TestWebhook(t *testing.T) {
	MaxClockDrift = -1

	body := []byte(`{"data":{"id":"dfd66777-8a60-411c-b61c-ad51c671c0bd","type":"webhook-events","attributes":{"endpoint":"https://5173-2600-1700-3e90-a450-533-a11e-339-f87b.ngrok.io","payload":"{\"data\":{\"id\":\"1598f237-f82f-448a-91f7-18d2c7e6fd41\",\"type\":\"licenses\",\"attributes\":{\"name\":\"Floating Demo License\",\"key\":\"DEMO-DAD877-FCBF82-B83D5A-03E644-V3\",\"expiry\":\"2023-01-01T00:00:00.000Z\",\"status\":\"ACTIVE\",\"uses\":0,\"suspended\":false,\"scheme\":null,\"encrypted\":false,\"strict\":false,\"floating\":true,\"concurrent\":false,\"protected\":true,\"maxMachines\":10,\"maxProcesses\":null,\"maxCores\":null,\"maxUses\":null,\"requireHeartbeat\":false,\"requireCheckIn\":false,\"lastValidated\":\"2022-06-06T16:03:28.185Z\",\"lastCheckIn\":null,\"nextCheckIn\":null,\"metadata\":{\"token\":\"activ-cd4f3a6c17707b94bacab29ab489ddf5v3\"},\"created\":\"2021-04-20T16:14:46.713Z\",\"updated\":\"2022-06-06T16:03:28.190Z\"},\"relationships\":{\"account\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52\"},\"data\":{\"type\":\"accounts\",\"id\":\"1fddcec8-8dd3-4d8d-9b16-215cac0f9b52\"}},\"product\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41/product\"},\"data\":{\"type\":\"products\",\"id\":\"42b9731d-21f2-4911-a066-d380a96c3a94\"}},\"policy\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41/policy\"},\"data\":{\"type\":\"policies\",\"id\":\"d048c5e6-b813-4e94-a346-d70726397457\"}},\"group\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41/group\"},\"data\":null},\"user\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41/user\"},\"data\":null},\"machines\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41/machines\"},\"meta\":{\"cores\":0,\"count\":1}},\"tokens\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41/tokens\"}},\"entitlements\":{\"links\":{\"related\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41/entitlements\"}}},\"links\":{\"self\":\"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/1598f237-f82f-448a-91f7-18d2c7e6fd41\"}},\"meta\":{\"ts\":\"2022-06-06T16:03:28.206Z\",\"valid\":true,\"detail\":\"is valid\",\"constant\":\"VALID\",\"scope\":{\"fingerprint\":\"cbce3fc7-0568-476d-a078-069a5d0500a2\",\"entitlements\":[\"DEMO_ENTITLEMENT\"]}}}","event":"license.validation.succeeded","status":"DELIVERING","lastResponseCode":null,"lastResponseBody":null,"created":"2022-06-06T16:03:28.243Z","updated":"2022-06-06T16:03:28.243Z"},"relationships":{"account":{"links":{"related":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"},"data":{"type":"accounts","id":"1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"}}},"links":{"self":"/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/webhook-events/dfd66777-8a60-411c-b61c-ad51c671c0bd"},"meta":{"idempotencyToken":"99b89d681aecdff9a0435c9f507d00c5345a7c2d6e773f1756e4a9d42e4b14v3"}}}`)
	url := `https://5173-2600-1700-3e90-a450-533-a11e-339-f87b.ngrok.io/webhooks`

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Should not fail creating a request: err=%v", err)
	}

	req.Header.Add("Keygen-Signature", `keyid="1fddcec8-8dd3-4d8d-9b16-215cac0f9b52", algorithm="ed25519", signature="oov4eX9ZC30U6l/OOOTH/IQF3NAlALlgBWQdh0LdG6WNtHbR95SoYJf2wOGMUGp2tYzNdSwlzPyepWozkKtXBg==", headers="(request-target) host date digest"`)
	req.Header.Add("Digest", `sha-256=9QceiZktviddaBO8zKZe18/L2kZSFwpGDcmvFkvIH3k=`)
	req.Header.Add("Date", `Mon, 06 Jun 2022 16:13:37 GMT`)

	if err := VerifyWebhook(req); err != nil {
		t.Fatalf("Should verify webhook: err=%v", err)
	}

	// Assert that the body can be read again
	b, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Should read webhook: err=%v", err)
	}

	if !bytes.Equal(b, body) {
		t.Fatalf("Body should match: actual=%s expected=%s", b, body)
	}
}

func TestHTTPClient(t *testing.T) {
	re := retryablehttp.NewClient()
	re.Backoff = retryablehttp.LinearJitterBackoff
	re.RetryMax = 5

	HTTPClient = re.StandardClient()
}
