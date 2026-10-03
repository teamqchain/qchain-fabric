/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/internal/cryptogen/ca"
	"github.com/hyperledger/fabric/internal/cryptogen/msp"
	"github.com/stretchr/testify/require"
)

func readSignCert(t *testing.T, nodeDir, name string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(nodeDir, "msp", "signcerts", name+"-cert.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestGenerateLocalMSPWithAttrs(t *testing.T) {
	for _, keyAlg := range []string{"mldsa44", ECDSA} {
		t.Run(keyAlg, func(t *testing.T) {
			dir := t.TempDir()
			signCA, err := ca.NewCA(filepath.Join(dir, "ca"), testCAOrg, testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode, keyAlg)
			require.NoError(t, err)
			tlsCA, err := ca.NewCA(filepath.Join(dir, "tlsca"), testCAOrg, "tls"+testCAName, testCountry, testProvince, testLocality, testOrganizationalUnit, testStreetAddress, testPostalCode, keyAlg)
			require.NoError(t, err)

			name := "issuer1@" + testCAOrg
			nodeDir := filepath.Join(dir, "issuer")
			err = msp.GenerateLocalMSPWithAttrs(nodeDir, name, nil, signCA, tlsCA, msp.CLIENT, true, keyAlg, map[string]string{"role": "issuer"})
			require.NoError(t, err)

			cert := readSignCert(t, nodeDir, name)
			var ext []byte
			for _, e := range cert.Extensions {
				if e.Id.Equal(ca.AttrOID) {
					require.False(t, e.Critical, "attribute extension must be non-critical")
					ext = e.Value
				}
			}
			require.NotNil(t, ext, "attribute extension missing")
			require.JSONEq(t, `{"attrs":{"role":"issuer"}}`, string(ext))
			var parsed struct {
				Attrs map[string]string `json:"attrs"`
			}
			require.NoError(t, json.Unmarshal(ext, &parsed))
			require.Equal(t, "issuer", parsed.Attrs["role"])

			require.NoError(t, cert.CheckSignatureFrom(signCA.SignCert), "cert must verify against the signing CA")
			roots := x509.NewCertPool()
			roots.AddCert(signCA.SignCert)
			_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			require.NoError(t, err)

			// Without attrs, no attribute extension is added.
			plain := "user1@" + testCAOrg
			plainDir := filepath.Join(dir, "plain")
			require.NoError(t, msp.GenerateLocalMSP(plainDir, plain, nil, signCA, tlsCA, msp.CLIENT, true, keyAlg))
			for _, e := range readSignCert(t, plainDir, plain).Extensions {
				require.False(t, e.Id.Equal(ca.AttrOID), "unexpected attribute extension")
			}
		})
	}
}
