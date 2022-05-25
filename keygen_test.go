package keygen

import (
	"os"
	"testing"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"
)

func init() {
	log := Logger.(*LeveledLogger)
	log.Level = LogLevelDebug

	if url := os.Getenv("KEYGEN_CUSTOM_DOMAIN"); url != "" {
		APIURL = url
	}

	PublicKey = os.Getenv("KEYGEN_PUBLIC_KEY")
	Account = os.Getenv("KEYGEN_ACCOUNT")
	Product = os.Getenv("KEYGEN_PRODUCT")
	LicenseKey = os.Getenv("KEYGEN_LICENSE_KEY")
	Token = os.Getenv("KEYGEN_TOKEN")
	Executable = "test"
	Logger = log
}

func TestValidate(t *testing.T) {
	fingerprint, err := machineid.ProtectedID(Account)
	if err != nil {
		t.Fatalf("Should fingerprint the current machine: err=%v", err)
	}

	license, err := Validate(fingerprint)
	if err == nil {
		t.Fatalf("Should not be activated: err=%v", err)
	}

	switch err.(type) {
	case *LicenseTokenInvalidError:
		t.Fatalf("Should be a valid license token: err=%v", err)
	case *LicenseKeyInvalidError:
		t.Fatalf("Should be a valid license key: err=%v", err)
	}

	switch {
	case err == ErrLicenseInvalid:
		t.Fatalf("Should be a valid license: err=%v", err)
	case err == ErrLicenseNotActivated:
		if license.ID == "" {
			t.Fatalf("Should have a correctly set license ID: license=%v", license)
		}

		if ts := license.LastValidated; ts == nil || time.Now().Add(time.Duration(-time.Second)).After(*ts) {
			t.Fatalf("Should have a correct last validated timestamp: ts=%v", ts)
		}

		keyDataset, err := license.Verify()
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

		licDataset, err := lic.Decrypt(license.Key)
		if err != nil {
			t.Fatalf("Should not fail decrypt: err=%v", err)
		}

		switch {
		case licDataset.License.ID != license.ID:
			t.Fatalf("Should have the correct license ID: actual=%s expected=%s", licDataset.License.ID, license.ID)
		case len(licDataset.Entitlements) == 0:
			t.Fatalf("Should have at least 1 entitlement: entitlements=%s", licDataset.Entitlements)
		case licDataset.Issued.IsZero():
			t.Fatalf("Should have an issued timestamp: ts=%v", licDataset.Issued)
		case licDataset.Expiry.IsZero():
			t.Fatalf("Should have an expiry timestamp: ts=%v", licDataset.Expiry)
		case licDataset.TTL == 0:
			t.Fatalf("Should have a TTL: ttl=%d", licDataset.TTL)
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

		micDataset, err := mic.Decrypt(license.Key + machine.Fingerprint)
		if err != nil {
			t.Fatalf("Should not fail decrypt: err=%v", err)
		}

		switch {
		case micDataset.Machine.ID != machine.ID:
			t.Fatalf("Should have the correct machine ID: actual=%s expected=%s", micDataset.Machine.ID, machine.ID)
		case micDataset.License.ID != license.ID:
			t.Fatalf("Should have the correct license ID: actual=%s expected=%s", micDataset.License.ID, license.ID)
		case len(micDataset.Entitlements) == 0:
			t.Fatalf("Should have at least 1 entitlement: entitlements=%s", micDataset.Entitlements)
		case micDataset.Issued.IsZero():
			t.Fatalf("Should have an issued timestamp: ts=%v", micDataset.Issued)
		case micDataset.Expiry.IsZero():
			t.Fatalf("Should have an expiry timestamp: ts=%v", micDataset.Expiry)
		case micDataset.TTL == 0:
			t.Fatalf("Should have a TTL: ttl=%d", micDataset.TTL)
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
		if e, ok := err.(*NotFoundError); !ok {
			t.Fatalf("Should already be deactivated: err=%v", e)
		}

		entitlements, err := license.Entitlements()
		if err != nil {
			t.Fatalf("Should not fail to list entitlements: err=%v", err)
		}

		t.Logf(
			"license=%v machines=%v entitlements=%v key=%s lic=%v mic=%v",
			license,
			machines,
			entitlements,
			keyDataset,
			licDataset,
			micDataset,
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
	if err != nil {
		t.Fatalf("License file decryption failed: err=%v", err)
	}

	t.Logf("dataset=%v\n", dataset)
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
	if err != nil {
		t.Fatalf("Machine file decryption failed: err=%v", err)
	}

	t.Logf("dataset=%v\n", dataset)
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

	t.Logf("dataset=%s\n", dataset)
}

func TestUpgrade(t *testing.T) {
	outdated := UpgradeOptions{CurrentVersion: "1.0.0", Channel: "stable", PublicKey: os.Getenv("KEYGEN_PERSONAL_PUBLIC_KEY")}
	upgrade, err := Upgrade(outdated)
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

	latest := UpgradeOptions{CurrentVersion: "1.0.1", Channel: "stable", PublicKey: os.Getenv("KEYGEN_PERSONAL_PUBLIC_KEY")}
	_, err = Upgrade(latest)
	if err != ErrUpgradeNotAvailable {
		t.Fatalf("Should not have an upgrade available: err=%v", err)
	}

	bad := UpgradeOptions{CurrentVersion: "2.0.0", Channel: "stable", PublicKey: os.Getenv("KEYGEN_PERSONAL_PUBLIC_KEY")}
	_, err = Upgrade(bad)
	if err != ErrUpgradeNotAvailable {
		t.Fatalf("Should not have an upgrade available: err=%v", err)
	}

	t.Logf("upgrade=%v", upgrade)
}

func TestParameterize(t *testing.T) {
	cases := [][]string{
		{"keygen darwin amd64 1.0.0", "keygen_darwin_amd64_1_0_0"},
		{"keygen linux arm64 2.0.0-beta.1", "keygen_linux_arm64_2_0_0_beta_1"},
		{"keygen windows 386 2.0.0+build.1653510415", "keygen_windows_386_2_0_0_build_1653510415"},
		{"keygen freebsd arm 2.0.0-rc.1+1653510415", "keygen_freebsd_arm_2_0_0_rc_1_1653510415"},
	}

	for _, c := range cases {
		in := c[0]
		expected := c[1]

		if out := parameterize(in); out != expected {
			t.Fatalf("Should parameterize input: in=%s out=%s expected=%s", in, out, expected)
		}
	}
}
