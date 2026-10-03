//go:build pqc

package msp

import (
	"crypto"
	"crypto/x509"
	"io"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	pqc "github.com/hyperledger/fabric-lib-go/bccsp-pqc"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	mspconfig "github.com/hyperledger/fabric-protos-go-apiv2/msp"
)

type pqcTestSigner struct {
	csp bccsp.BCCSP
	key bccsp.Key
}

func (s *pqcTestSigner) Public() crypto.PublicKey { return nil }

func (s *pqcTestSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.csp.Sign(s.key, digest, nil)
}

func TestPQCSigningIdentity(t *testing.T) {
	csp, err := factory.GetBCCSPFromOpts(&factory.FactoryOpts{
		Default: "PQC",
		PQC:     &factory.PQCOpts{KeyStorePath: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("create PQC BCCSP: %v", err)
	}

	privateKey, err := csp.KeyGen(&pqc.KeyGenOpts{AlgorithmName: pqc.MLDSA44, Temporary: true})
	if err != nil {
		t.Fatalf("generate ML-DSA key: %v", err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatalf("get ML-DSA public key: %v", err)
	}

	mspInstance, err := newBccspMsp(MSPv3_0, csp)
	if err != nil {
		t.Fatalf("create MSP: %v", err)
	}
	internalMSP := mspInstance.(*bccspmsp)
	internalMSP.cryptoConfig = &mspconfig.FabricCryptoConfig{
		SignatureHashFamily:            bccsp.SHA2,
		IdentityIdentifierHashFunction: bccsp.SHA256,
	}

	identity, err := newSigningIdentity(
		&x509.Certificate{Raw: []byte("synthetic ML-DSA certificate"), PublicKeyAlgorithm: x509.MLDSA},
		publicKey,
		&pqcTestSigner{csp: csp, key: privateKey},
		internalMSP,
	)
	if err != nil {
		t.Fatalf("create MSP signing identity: %v", err)
	}

	message := []byte("MSP-level ML-DSA signing test")
	signature, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("sign through MSP identity: %v", err)
	}
	if err := identity.Verify(message, signature); err != nil {
		t.Fatalf("verify through MSP identity: %v", err)
	}
	if err := identity.Verify([]byte("changed message"), signature); err == nil {
		t.Fatal("signature verified for a different message")
	}
}
