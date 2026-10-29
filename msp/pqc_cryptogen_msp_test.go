//go:build pqc

package msp

import (
	"os"
	"path/filepath"
	"testing"

	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
)

func TestPQCCryptogenMSP(t *testing.T) {
	mspDir := os.Getenv("PQC_MSP_DIR")
	if mspDir == "" {
		t.Skip("PQC_MSP_DIR not set")
	}
	mspID := os.Getenv("PQC_MSP_ID")
	if mspID == "" {
		mspID = "GovernmentMSP"
	}

	// cryptogen's keystore (holds priv_sk). Treated as read-only.
	keystoreDir := filepath.Join(mspDir, "keystore")

	csp, err := pqc.NewWithFileKeyStore(keystoreDir, nil)
	if err != nil {
		t.Fatalf("NewWithFileKeyStore: %v", err)
	}

	bccspConfig := &factory.FactoryOpts{
		Default: "PQC",
		PQC:     &factory.PQCOpts{KeyStorePath: keystoreDir},
	}

	mspConfig, err := GetLocalMspConfig(mspDir, bccspConfig, mspID)
	if err != nil {
		t.Fatalf("GetLocalMspConfig: %v", err)
	}

	localMSP, err := New(&BCCSPNewOpts{NewBaseOpts: NewBaseOpts{Version: MSPv3_0}}, csp)
	if err != nil {
		t.Fatalf("msp.New: %v", err)
	}
	if err := localMSP.Setup(mspConfig); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	signingID, err := localMSP.GetDefaultSigningIdentity()
	if err != nil {
		t.Fatalf("GetDefaultSigningIdentity: %v", err)
	}

	msg := []byte("real end-to-end MSP signing test")
	sig, err := signingID.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signingID.Verify(msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Log("PASSED: cryptogen ML-DSA MSP -> Setup -> Sign/Verify")
}
