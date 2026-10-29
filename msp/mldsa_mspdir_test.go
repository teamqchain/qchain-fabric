/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto"
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
)

// writeMLDSAMSPDir lays out an MSP directory in dir: a self-signed ML-DSA-44
// root in cacerts/, and a leaf for leafPub signed by that root in signcerts/
// and admincerts/. It uses only crypto/mldsa and crypto/x509, so it works in
// every build. It returns the root certificate and key.
func writeMLDSAMSPDir(t *testing.T, dir string, leafPub crypto.PublicKey) (*x509.Certificate, crypto.Signer) {
	t.Helper()
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
	return rootCert, rootPriv
}
