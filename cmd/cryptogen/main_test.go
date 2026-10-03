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

func TestUserNodeSpecs(t *testing.T) {
	specs, err := userNodeSpecs(UsersSpec{
		Count:              2,
		PublicKeyAlgorithm: "mldsa44",
		Specs: []UserSpec{
			{Name: "issuer1", Attrs: map[string]string{"role": "issuer"}},
			{Name: "plain1"},
		},
	}, "example.com")
	require.NoError(t, err)
	require.Len(t, specs, 4)
	require.Equal(t, "User1@example.com", specs[0].CommonName)
	require.Equal(t, "User2@example.com", specs[1].CommonName)
	require.Nil(t, specs[1].attrs)
	require.Equal(t, "issuer1@example.com", specs[2].CommonName)
	require.Equal(t, map[string]string{"role": "issuer"}, specs[2].attrs)
	require.Equal(t, "plain1@example.com", specs[3].CommonName)
	require.Empty(t, specs[3].attrs)
	for _, s := range specs {
		require.Equal(t, "mldsa44", s.PublicKeyAlgorithm)
	}

	for _, bad := range []string{"", "Admin", "User1", "a@b", "a/b"} {
		_, err := userNodeSpecs(UsersSpec{Count: 1, Specs: []UserSpec{{Name: bad}}}, "example.com")
		require.Error(t, err, "name %q should be rejected", bad)
	}
	_, err = userNodeSpecs(UsersSpec{Specs: []UserSpec{{Name: "x"}, {Name: "x"}}}, "example.com")
	require.Error(t, err, "duplicate names should be rejected")
}
