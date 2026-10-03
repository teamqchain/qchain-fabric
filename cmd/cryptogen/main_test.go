/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"
)

func TestDefaultConfigParsing(t *testing.T) {
	config := &Config{}
	err := yaml.Unmarshal([]byte(defaultConfig), &config)
	require.NoError(t, err)
}

func TestGetAdminPublicKeyAlg(t *testing.T) {
	tests := []struct {
		name    string
		orgSpec OrgSpec
		want    string
	}{
		{
			name: "users algorithm wins",
			orgSpec: OrgSpec{
				CA:    NodeSpec{PublicKeyAlgorithm: ED25519},
				Users: UsersSpec{PublicKeyAlgorithm: "mldsa44"},
			},
			want: "mldsa44",
		},
		{
			name:    "falls back to CA algorithm",
			orgSpec: OrgSpec{CA: NodeSpec{PublicKeyAlgorithm: "mldsa44"}},
			want:    "mldsa44",
		},
		{
			name:    "falls back to default",
			orgSpec: OrgSpec{},
			want:    ECDSA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, getAdminPublicKeyAlg(tt.orgSpec))
		})
	}
}
