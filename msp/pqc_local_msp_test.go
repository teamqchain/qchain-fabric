//go:build pqc

// ~/fabric/msp/pqc_local_msp_test.go
package msp

import (
	"crypto/mldsa"
	"path/filepath"
	"testing"

	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
)

func TestPQCLocalMSPRealCerts(t *testing.T) {
	dir := t.TempDir()
	keystoreDir := filepath.Join(dir, "keystore")

	// 1. Generate the LEAF signing key through the PQC BCCSP, non-ephemeral,
	//    so it lands in keystore/ under its own SKI — exactly where the
	//    MSP's BCCSP.GetKey(ski) will look for it later.
	csp, err := pqc.NewWithFileKeyStore(keystoreDir, nil)
	if err != nil {
		t.Fatalf("NewWithFileKeyStore: %v", err)
	}
	leafKey, err := csp.KeyGen(&pqc.KeyGenOpts{AlgorithmName: pqc.MLDSA44})
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	leafRawPub, err := pqc.PublicKeyBytes(leafKey)
	if err != nil {
		t.Fatalf("PublicKeyBytes: %v", err)
	}
	leafPub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), leafRawPub)
	if err != nil {
		t.Fatalf("mldsa.NewPublicKey: %v", err)
	}

	// 2-4. Root CA (native mldsa — proven interoperable with the BCCSP key
	//      above), a leaf for the BCCSP key, and the MSP directory layout.
	writeMLDSAMSPDir(t, dir, leafPub)

	// 5. Point the real BCCSP factory at your PQC provider, same keystore dir.
	bccspConfig := &factory.FactoryOpts{
		Default: "PQC",
		PQC:     &factory.PQCOpts{KeyStorePath: keystoreDir},
	}

	mspConfig, err := GetLocalMspConfig(dir, bccspConfig, "GovernmentMSP")
	if err != nil {
		t.Fatalf("GetLocalMspConfig: %v", err)
	}

	/* localMSP, err := New(&BCCSPNewOpts{NewBaseOpts: NewBaseOpts{Version: MSPv3_0}}, factory.GetDefault()) */
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
	t.Log("PASSED: real ML-DSA cert -> GetLocalMspConfig -> Setup -> SigningIdentity.Sign/Verify")
}
