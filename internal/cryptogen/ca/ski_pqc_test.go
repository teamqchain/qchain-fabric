//go:build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ca

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
)

// TestMLDSA44SKIMatchesPQCBCCSP proves cryptogen's computeSKI and the PQC
// BCCSP key's SKI() are byte-identical for the same ML-DSA-44 public key.
func TestMLDSA44SKIMatchesPQCBCCSP(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cryptogenSKI, err := computeSKI(priv)
	if err != nil {
		t.Fatalf("computeSKI: %v", err)
	}

	csp, err := pqc.NewWithFileKeyStore(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewWithFileKeyStore: %v", err)
	}

	// Raw public key import.
	rawKey, err := csp.KeyImport(priv.PublicKey().Bytes(), &pqc.PublicKeyImportOpts{AlgorithmName: pqc.MLDSA44, Temporary: true})
	if err != nil {
		t.Fatalf("KeyImport raw: %v", err)
	}
	if !bytes.Equal(cryptogenSKI, rawKey.SKI()) {
		t.Fatalf("raw import SKI mismatch:\n cryptogen %x\n bccsp     %x", cryptogenSKI, rawKey.SKI())
	}

	// X509 import: the path the MSP uses to derive the SKI it looks up.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ski-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		SubjectKeyId: cryptogenSKI,
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, priv.PublicKey(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	certKey, err := csp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		t.Fatalf("KeyImport x509: %v", err)
	}
	if !bytes.Equal(cryptogenSKI, certKey.SKI()) {
		t.Fatalf("x509 import SKI mismatch:\n cryptogen %x\n bccsp     %x", cryptogenSKI, certKey.SKI())
	}
	if !bytes.Equal(cert.SubjectKeyId, certKey.SKI()) {
		t.Fatalf("cert SubjectKeyId %x != bccsp SKI %x", cert.SubjectKeyId, certKey.SKI())
	}
}

// importSeedKey imports a crypto/mldsa key into the PQC BCCSP via its 32-byte seed.
func importSeedKey(t *testing.T, csp bccsp.BCCSP, priv *mldsa.PrivateKey) bccsp.Key {
	t.Helper()
	k, err := csp.KeyImport(priv.Bytes(), &pqc.PrivateKeyImportOpts{
		AlgorithmName: pqc.MLDSA44,
		Temporary:     true,
		PublicKey:     priv.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("PrivateKeyImportOpts rejected crypto/mldsa seed: %v", err)
	}
	return k
}

// TestMLDSA44SeedPrivateKeyImport is a regression test: the PQC BCCSP must
// accept the 32-byte seed crypto/mldsa (and so cryptogen) produces, and the
// resulting key's public bytes and SKI must match cryptogen's.
func TestMLDSA44SeedPrivateKeyImport(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csp, err := pqc.NewWithFileKeyStore(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewWithFileKeyStore: %v", err)
	}
	if len(priv.Bytes()) != mldsa.PrivateKeySize {
		t.Fatalf("mldsa.PrivateKey.Bytes() length %d, want seed size %d", len(priv.Bytes()), mldsa.PrivateKeySize)
	}
	k := importSeedKey(t, csp, priv)
	if !k.Private() {
		t.Fatal("imported key is not private")
	}
	pub, err := pqc.PublicKeyBytes(k)
	if err != nil {
		t.Fatalf("PublicKeyBytes: %v", err)
	}
	if !bytes.Equal(pub, priv.PublicKey().Bytes()) {
		t.Fatal("public key bytes differ from crypto/mldsa")
	}
	cryptogenSKI, err := computeSKI(priv)
	if err != nil {
		t.Fatalf("computeSKI: %v", err)
	}
	if !bytes.Equal(k.SKI(), cryptogenSKI) {
		t.Fatalf("SKI mismatch:\n cryptogen %x\n bccsp     %x", cryptogenSKI, k.SKI())
	}

	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, err = csp.KeyImport(priv.Bytes(), &pqc.PrivateKeyImportOpts{
		AlgorithmName: pqc.MLDSA44,
		Temporary:     true,
		PublicKey:     other.PublicKey().Bytes(),
	})
	if err == nil {
		t.Fatal("seed import accepted a mismatched public key")
	}
}

// TestMLDSA44CrossImplementation checks that crypto/mldsa and liboqs
// signatures interoperate through the PQC BCCSP.
func TestMLDSA44CrossImplementation(t *testing.T) {
	csp, err := pqc.NewWithFileKeyStore(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("NewWithFileKeyStore: %v", err)
	}
	msg := []byte("cross-implementation ML-DSA-44")

	t.Run("seed key signs via Go, liboqs verifies", func(t *testing.T) {
		priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		k := importSeedKey(t, csp, priv)
		sig, err := csp.Sign(k, msg, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		pubKey, err := k.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		// csp.Verify always uses liboqs.
		ok, err := csp.Verify(pubKey, sig, msg, nil)
		if err != nil || !ok {
			t.Fatalf("liboqs Verify of Go signature: ok=%v err=%v", ok, err)
		}
		if err := mldsa.Verify(priv.PublicKey(), msg, sig, nil); err != nil {
			t.Fatalf("Go Verify of Go signature: %v", err)
		}
	})

	t.Run("liboqs key signs, Go verifies", func(t *testing.T) {
		k, err := csp.KeyGen(&pqc.KeyGenOpts{AlgorithmName: pqc.MLDSA44, Temporary: true})
		if err != nil {
			t.Fatalf("KeyGen: %v", err)
		}
		sig, err := csp.Sign(k, msg, nil)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		rawPub, err := pqc.PublicKeyBytes(k)
		if err != nil {
			t.Fatalf("PublicKeyBytes: %v", err)
		}
		goPub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), rawPub)
		if err != nil {
			t.Fatalf("NewPublicKey: %v", err)
		}
		if err := mldsa.Verify(goPub, msg, sig, nil); err != nil {
			t.Fatalf("Go Verify of liboqs signature: %v", err)
		}
	})
}

// TestPQCKeystoreScanFindsPKCS8Seed checks GetKey falls back to scanning the
// keystore for a cryptogen-style priv_sk, without writing to the directory.
func TestPQCKeystoreScanFindsPKCS8Seed(t *testing.T) {
	dir := t.TempDir()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	files := map[string][]byte{
		"aaa_junk": []byte("not a pem"),
		"priv_sk":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherSKI, _ := computeSKI(other)
	wantSKI, _ := computeSKI(priv)

	csp, err := pqc.NewWithFileKeyStore(dir, nil)
	if err != nil {
		t.Fatalf("NewWithFileKeyStore: %v", err)
	}
	if _, err := csp.GetKey(otherSKI); err == nil {
		t.Fatal("GetKey found a key for a non-matching SKI")
	}
	k, err := csp.GetKey(wantSKI)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if !k.Private() || !bytes.Equal(k.SKI(), wantSKI) {
		t.Fatalf("GetKey returned wrong key: private=%v ski=%x", k.Private(), k.SKI())
	}
	sig, err := csp.Sign(k, []byte("msg"), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := mldsa.Verify(priv.PublicKey(), []byte("msg"), sig, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(files) {
		t.Fatalf("keystore written to: %d entries, want %d", len(entries), len(files))
	}
}
