/*******************************************************************************
* Copyright 2021 Intel Corporation
* Copyright 2020 Redis Labs
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
* in compliance with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software distributed under the License
* is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
* or implied. See the License for the specific language governing permissions and limitations under
* the License.
*
*******************************************************************************/

package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/helper"
	"github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/kong/config"
	"github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/kong/container"
	bootstrapContainer "github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
)

const (

	// These prefixes are for "pretty" & "scoped" logging purposes only
	cmdPrefix  string = "[build-kong-admin]"
	errPrefix  string = cmdPrefix + "[error]"
	infoPrefix string = cmdPrefix + "[info]"
)

// Handler is the main struct for the Kong Admin API Loopback setup
type Handler struct {
	logger logger.LoggingClient
	config *config.ConfigurationStruct
	keys   KeyInfo
	jwt    JWTInfo
}

// KeyInfo stores EC public/private key information
type KeyInfo struct {
	publicKey    string
	privateKey   string
	privateKeyEC *ecdsa.PrivateKey
}

// JWTInfo stores JWT issuer and the generated token -> signedToken
type JWTInfo struct {
	issuer      string
	signedToken string
}

// NewHandler returns a preset Handler struct
func NewHandler(dic *di.Container) *Handler {

	// Get configuration from the dependency injector
	// configuration := &config.ConfigurationStruct{}
	// dic := di.NewContainer(di.ServiceConstructorMap{
	// 	container.ConfigurationName: func(get di.Get) interface{} {
	// 		return configuration
	// 	},
	// })

	// Return struct
	return &Handler{
		logger: bootstrapContainer.LoggingClientFrom(dic.Get),
		config: container.ConfigurationFrom(dic.Get),
		keys:   KeyInfo{},
		jwt:    JWTInfo{},
	}
}

// SetupLoopbackAPI is the default function for execution of CLI switches from the
// parent binary "edgex-security-bootstrapper". This function specifically
// exposes Admin API functionality in Kong through a "Loopback" API call
// that is protected by use of a JWT.
//
// -- API exposed @ http://<the-host>:8000/admin
//
// The JWT and Private Key generated within this code block is stored within
// the EdgeX Secret Store. The Private Key is stored in the event that a
// new JWT needs to be generated for the "admin" user in Kong.
func (h *Handler) SetupLoopbackAPI(ctx context.Context, _ *sync.WaitGroup, startupTimer startup.Timer,
	dic *di.Container) bool {

	// Setup vars
	var err error
	// logger := bootstrapContainer.LoggingClientFrom(dic.Get)
	// secretProvider := bootstrapContainer.SecretProviderFrom(dic.Get)

	h.logger.Infof("%s Loopback API setup is starting", cmdPrefix)

	// Create an EC private/public
	// ------------------------------------------------------------------------
	// This section creates an EC based public/private key pair. The byte
	// version of the private key and string version of both keys are stored
	// in the Handler{} struct (although now I'm thinking it might not be
	// necessary). //TODO: Is it still necessary?
	// ------------------------------------------------------------------------
	h.keys.privateKeyEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.logger.Errorf("%s Failed to generate private/public key pair: %w", errPrefix, err)
		return false
	}
	encodedPrivateKey, encodedPublicKey := h.getEncodedKeys(h.keys.privateKeyEC)

	// Store string versions of keys in struct and destroy on complete
	// ------------------------------------------------------------------------
	// The string versions of the keys are useful in two ways:
	//	- Private key string is stored in Vault for future JWT creation.
	//	- Public key string is inserted into the Kong configuration file.
	// ------------------------------------------------------------------------
	h.keys.privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivateKey}))
	h.keys.publicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedPublicKey}))

	defer h.clearSecrets()

	// Read in the configuration template
	// ------------------------------------------------------------------------
	// Template is located in "/cmd/security-bootstrapper/res-bootstrap-kong"
	// in the source code. In the Docker container, the template is located
	// in "/edgex-init/bootstrap-kong/configuration.toml".
	//
	// The default value for this variable is located in the Kong boostrap
	// configuration file --> "/cmd/security-bootstrapper/res-bootstrap-kong/
	// configuration.toml".
	//
	// This value can be modified by using the "--template_path" flag on the
	// command line, or modifying <var>.paths.templatePath after instantiating
	// a new Handler{}.
	// ------------------------------------------------------------------------
	configTemplateBytes, err := ioutil.ReadFile(h.config.KongPaths.TemplatePath)
	if err != nil {
		h.logger.Errorf("%s Failed to read config template from file %s: %w", errPrefix, h.config.KongPaths.TemplatePath, err)
		return false
	}

	// Inject public key & JWT issuer into template file
	// ------------------------------------------------------------------------
	// In "/cmd/security-bootstrapper/res-bootstrap-kong" there is a template
	// file that contains these string values to replace. That template file
	// can be modified to include any Kong configuration values that can be
	// set in a Declarative Config file.
	//
	// This is the value in the JSON payload that is sandwiched between the
	// public/private key vals during the tokenizing process.
	//
	// The public key replacement includes 4 spaces after each line ending
	// because the Kong config parser will invalidate the YML if it is not
	// present (as it does line the text up in the same column).
	// ------------------------------------------------------------------------

	// Completely random value for token generation
	h.jwt.issuer = helper.GenerateRandomString(32)

	// Insert public key
	configTemplateText := strings.Replace(string(configTemplateBytes),
		"<<INSERT-ADMIN-PUBLIC-KEY>>", strings.ReplaceAll(strings.TrimSpace(h.keys.publicKey), "\n", "\n    "), -1)

	// Insert issuer
	configTemplateText = strings.Replace(configTemplateText,
		"<<INSERT-ADMIN-JWT-ISSUER-KEY>>", h.jwt.issuer, -1)

	// Write new configuration file to disk
	// ------------------------------------------------------------------------
	// The modified configuration file is dropped to the default Kong config
	// path --> /usr/local/kong/kong.yml.
	//
	// This path can be modified by using the "--file_save_path" flag on the
	// command line, or modifying <var>.paths.fileSavePath after instantiating
	// a new Handler{}.
	// ------------------------------------------------------------------------
	err = ioutil.WriteFile(h.config.KongPaths.FileSavePath, []byte(configTemplateText), 0644)
	if err != nil {
		h.logger.Errorf("%s Failed to write config template to file %s: %w", errPrefix, h.config.KongPaths.FileSavePath, err)
		return false
	}

	// Generate JWT
	// ------------------------------------------------------------------------
	// createJWT will generate a JWT based on the private key passed in and the
	// issuer (both string vars) and store it in h.jwt.signedToken for later
	// use.
	// ------------------------------------------------------------------------
	h.jwt.signedToken, err = h.createJWT(h.keys.privateKey, h.jwt.issuer)
	if err != nil {
		h.logger.Errorf("%s Failed to create signed JSON Web Token: %w", errPrefix, err)
		return false
	}

	// Save JWT Token & Private Key in Vault
	// ------------------------------------------------------------------------
	// TODO: Create process to save the string values of the JWT and PK in the
	// TODO: secret provider (vault).
	// ------------------------------------------------------------------------
	// secretProvider.StoreSecrets()
	fmt.Printf("%s\n", h.jwt.signedToken)

	// And we're done...
	h.logger.Infof("%s Loopback API setup is complete", cmdPrefix)
	return true
}

// getEncodedKeys will return encoded values of a private & public key based
// on input from an ecdsa.PrivateKey pointer.
func (h *Handler) getEncodedKeys(key *ecdsa.PrivateKey) (privateKey []byte, publicKey []byte) {

	privateKey, _ = x509.MarshalECPrivateKey(key)
	publicKey, _ = x509.MarshalPKIXPublicKey(&key.PublicKey)

	return privateKey, publicKey
}

// createJWT creates a JSON web token based on the private key read in to
// memory. The JWT is stored in "cmd.jwt.signedToken" and nil is returned
// on successful execution.
func (h *Handler) createJWT(privateKey string, issuer string) (string, error) {

	// Setup JWT generation variables
	now := time.Now().Unix()
	duration, err := time.ParseDuration("1h")
	if err != nil {
		return "", fmt.Errorf("%s Could not parse JWT duration: %w", errPrefix, err)
	}

	// Sanity check - parse & check EC key
	eckey, err := jwt.ParseECPrivateKeyFromPEM([]byte(privateKey))
	if err == nil && eckey.Params().BitSize != 256 {
		return "", fmt.Errorf("%s EC key bit size is incorrect (%d instead of 256)", errPrefix, eckey.Params().BitSize)
	}
	if err != nil {
		return "", fmt.Errorf("%s Could not parse private key: %w", errPrefix, err)
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
		Issuer:    issuer,
		IssuedAt:  now,
		NotBefore: now,
		ExpiresAt: now + int64(duration.Seconds()),
	})

	// Save JWT to struct
	signedToken, err := token.SignedString(eckey)
	if err != nil {
		return "", fmt.Errorf("%s Could not sign JWT: %w", errPrefix, err)
	}

	return signedToken, nil
}

// clearSecrets() is a helper function to remove secret material saved in
// memory. This function runs at the end of Execute() via `defer`.
func (h *Handler) clearSecrets() {

	// Clear structs by setting them to empty struct values
	h.jwt = JWTInfo{}
	h.keys = KeyInfo{}
}
