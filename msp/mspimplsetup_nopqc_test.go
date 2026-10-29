//go:build !pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	m "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// mldsaImportBCCSP is the default SW BCCSP, except that it imports the public
// key of an ML-DSA certificate with crypto/mldsa. It stands in for a BCCSP
// that handles ML-DSA, which builds without the pqc tag do not have.
type mldsaImportBCCSP struct {
	bccsp.BCCSP
}

func (b mldsaImportBCCSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	if cert, ok := raw.(*x509.Certificate); ok {
		if pub, ok := cert.PublicKey.(*mldsa.PublicKey); ok {
			return mldsaPublicKey{pub}, nil
		}
	}
	return b.BCCSP.KeyImport(raw, opts)
}

type mldsaPublicKey struct{ pub *mldsa.PublicKey }

func (k mldsaPublicKey) Bytes() ([]byte, error)        { return x509.MarshalPKIXPublicKey(k.pub) }
func (k mldsaPublicKey) SKI() []byte                   { s := sha256.Sum256(k.pub.Bytes()); return s[:] }
func (k mldsaPublicKey) Symmetric() bool               { return false }
func (k mldsaPublicKey) Private() bool                 { return false }
func (k mldsaPublicKey) PublicKey() (bccsp.Key, error) { return k, nil }

const mldsaNotSupported = "could not validate identity's public key algorithm: ML-DSA is not supported"

// Without the pqc tag a v3 MSP does not accept ML-DSA identities, even with a
// BCCSP that can import their keys.
func TestMSPv3RejectsMLDSAWithoutPQCTag(t *testing.T) {
	leaf, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	dir := t.TempDir()
	rootCert, rootKey := writeMLDSAMSPDir(t, dir, leaf.PublicKey())
	csp := mldsaImportBCCSP{factory.GetDefault()}

	// The ML-DSA admin certificate is refused at Setup.
	conf, err := GetVerifyingMspConfig(dir, "GovernmentMSP", ProviderTypeToString(FABRIC))
	require.NoError(t, err)
	msp, err := New(&BCCSPNewOpts{NewBaseOpts: NewBaseOpts{Version: MSPv3_0}}, csp)
	require.NoError(t, err)
	require.EqualError(t, msp.Setup(conf), "admin 0 is invalid: "+mldsaNotSupported)

	// With an ECDSA admin under the same ML-DSA root, Setup succeeds, and an
	// ML-DSA identity is refused when it is validated.
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	adminTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "admin"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	adminDER, err := x509.CreateCertificate(rand.Reader, adminTemplate, rootCert, &adminKey.PublicKey, rootKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admincerts", "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: adminDER}), 0o644))
	conf, err = GetVerifyingMspConfig(dir, "GovernmentMSP", ProviderTypeToString(FABRIC))
	require.NoError(t, err)
	msp, err = New(&BCCSPNewOpts{NewBaseOpts: NewBaseOpts{Version: MSPv3_0}}, csp)
	require.NoError(t, err)
	require.NoError(t, msp.Setup(conf))

	leafPEM, err := os.ReadFile(filepath.Join(dir, "signcerts", "cert.pem"))
	require.NoError(t, err)
	serialized, err := proto.Marshal(&m.SerializedIdentity{Mspid: "GovernmentMSP", IdBytes: leafPEM})
	require.NoError(t, err)
	id, err := msp.DeserializeIdentity(serialized)
	require.NoError(t, err)
	require.EqualError(t, id.Validate(), mldsaNotSupported)
}

// With the default SW BCCSP an MSP with an ML-DSA root does not set up at
// all: the BCCSP cannot import the root's public key.
func TestMSPv3SWBCCSPRejectsMLDSARoot(t *testing.T) {
	leaf, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	dir := t.TempDir()
	writeMLDSAMSPDir(t, dir, leaf.PublicKey())
	conf, err := GetVerifyingMspConfig(dir, "GovernmentMSP", ProviderTypeToString(FABRIC))
	require.NoError(t, err)
	msp, err := New(&BCCSPNewOpts{NewBaseOpts: NewBaseOpts{Version: MSPv3_0}}, factory.GetDefault())
	require.NoError(t, err)
	err = msp.Setup(conf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: [ECDSA, ED25519, RSA]")
}
