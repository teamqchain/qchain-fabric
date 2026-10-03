// ~/fabric/msp/pqc_local_msp_test.go
package msp

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
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

	// 2. Root CA (native mldsa — proven interoperable with the BCCSP key above).
	rootPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("root GenerateKey: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "GovernmentMSP-root"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPriv.PublicKey(), rootPriv)
	if err != nil {
		t.Fatalf("root CreateCertificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("root ParseCertificate: %v", err)
	}

	// 3. Leaf cert, signed by root, wrapping the BCCSP-generated key.
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "peer0.government.uae.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, leafPub, rootPriv)
	if err != nil {
		t.Fatalf("leaf CreateCertificate: %v", err)
	}

	// 4. Lay out the real MSP directory structure.
	writePEM := func(subdir, name string, der []byte) {
		d := filepath.Join(dir, subdir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
		if err := os.WriteFile(filepath.Join(d, name), pem.EncodeToMemory(block), 0o644); err != nil {
			t.Fatalf("write %s/%s: %v", d, name, err)
		}
	}
	writePEM("cacerts", "ca.pem", rootDER)
	writePEM("signcerts", "cert.pem", leafDER)
	writePEM("admincerts", "cert.pem", leafDER)

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