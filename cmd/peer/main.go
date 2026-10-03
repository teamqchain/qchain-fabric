/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"hash"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric/internal/peer/chaincode"
	"github.com/hyperledger/fabric/internal/peer/channel"
	"github.com/hyperledger/fabric/internal/peer/common"
	"github.com/hyperledger/fabric/internal/peer/lifecycle"
	"github.com/hyperledger/fabric/internal/peer/node"
	"github.com/hyperledger/fabric/internal/peer/snapshot"
	"github.com/hyperledger/fabric/internal/peer/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// The main command describes the service and
// defaults to printing the help message.
var mainCmd = &cobra.Command{Use: "peer"}

func main() {
	setEnvConfig(viper.GetViper())

	// Define command-line flags that are valid for all peer commands and
	// subcommands.
	mainFlags := mainCmd.PersistentFlags()

	mainFlags.String("logging-level", "", "Legacy logging level flag")
	viper.BindPFlag("logging_level", mainFlags.Lookup("logging-level"))
	mainFlags.MarkHidden("logging-level")

	// Commands are built before InitCmd initializes the BCCSP factories, so
	// resolve the default provider lazily, at call time.
	cryptoProvider := lazyBCCSP{}

	mainCmd.AddCommand(version.Cmd())
	mainCmd.AddCommand(node.Cmd())
	mainCmd.AddCommand(chaincode.Cmd(nil, cryptoProvider))
	mainCmd.AddCommand(channel.Cmd(nil))
	mainCmd.AddCommand(lifecycle.Cmd(cryptoProvider))
	mainCmd.AddCommand(snapshot.Cmd(cryptoProvider))

	// On failure Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if mainCmd.Execute() != nil {
		os.Exit(1)
	}
}

func setEnvConfig(v *viper.Viper) {
	v.SetEnvPrefix(common.CmdRoot)
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	v.SetEnvKeyReplacer(replacer)
}

// lazyBCCSP delegates every call to factory.GetDefault(). Calling GetDefault
// before InitFactories returns the SW boot BCCSP, which cannot handle a
// non-SW configuration (e.g. PQC/ML-DSA channel MSPs).
type lazyBCCSP struct{}

func (lazyBCCSP) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	return factory.GetDefault().KeyGen(opts)
}

func (lazyBCCSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	return factory.GetDefault().KeyDeriv(k, opts)
}

func (lazyBCCSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	return factory.GetDefault().KeyImport(raw, opts)
}

func (lazyBCCSP) GetKey(ski []byte) (bccsp.Key, error) {
	return factory.GetDefault().GetKey(ski)
}

func (lazyBCCSP) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	return factory.GetDefault().Hash(msg, opts)
}

func (lazyBCCSP) GetHash(opts bccsp.HashOpts) (hash.Hash, error) {
	return factory.GetDefault().GetHash(opts)
}

func (lazyBCCSP) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return factory.GetDefault().Sign(k, digest, opts)
}

func (lazyBCCSP) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return factory.GetDefault().Verify(k, signature, digest, opts)
}

func (lazyBCCSP) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	return factory.GetDefault().Encrypt(k, plaintext, opts)
}

func (lazyBCCSP) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	return factory.GetDefault().Decrypt(k, ciphertext, opts)
}
