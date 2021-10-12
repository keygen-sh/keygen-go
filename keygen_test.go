package keygen

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"os"
	"testing"
)

func TestValidate(t *testing.T) {
	Account = os.Getenv("KEYGEN_ACCOUNT")
	Product = os.Getenv("KEYGEN_PRODUCT")
	Token = os.Getenv("KEYGEN_TOKEN")

	fingerprint := randomString(32)
	license, err := Validate(fingerprint)
	switch {
	case err == ErrLicenseNotActivated:
		machine, err := license.Activate(fingerprint)
		if err != nil {
			t.Fatalf("Should not fail activation: err=%v", err)
		}

		go machine.Monitor()

		machines, err := license.Machines()
		if err != nil {
			t.Fatalf("Should not fail to list machines: err=%v", err)
		}

		for _, machine := range machines {
			err = machine.Deactivate()
			if err != nil {
				t.Fatalf("Should not fail deactivation: err=%v", err)
			}
		}

		entitlements, err := license.Entitlements()
		if err != nil {
			t.Fatalf("Should not fail to list entitlements: err=%v", err)
		}

		t.Logf("INFO: license=%v machines=%v entitlements=%v", license, machines, entitlements)
	case err != nil:
		t.Fatalf("Should not fail validation: err=%v", err)
	}

	t.Logf("INFO: license=%v", license)
}

func randomString(l int) string {
	buff := make([]byte, int(math.Ceil(float64(l)/2)))
	rand.Read(buff)
	str := hex.EncodeToString(buff)
	return str[:l]
}
