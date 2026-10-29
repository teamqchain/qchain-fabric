//go:build !pqc

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import "crypto/x509"

// pqcPublicKeyAlgorithms returns no algorithms: without the pqc build tag
// there is no PQC BCCSP, so a v3 MSP does not accept ML-DSA identities.
func pqcPublicKeyAlgorithms() []x509.PublicKeyAlgorithm {
	return nil
}
