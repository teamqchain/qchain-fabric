//go:build pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import "crypto/x509"

// pqcPublicKeyAlgorithms returns the post-quantum public key algorithms a v3
// MSP accepts: ML-DSA, whose keys only the PQC BCCSP handles.
func pqcPublicKeyAlgorithms() []x509.PublicKeyAlgorithm {
	return []x509.PublicKeyAlgorithm{x509.MLDSA}
}
