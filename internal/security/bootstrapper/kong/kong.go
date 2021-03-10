/*******************************************************************************
* Copyright 2021 Intel Corporation
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
* @author: Beau Frusetta <beau.frusetta@intel.com>
*
*******************************************************************************/

package kong

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/edgexfoundry/edgex-go/internal"
	"github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/kong/config"
	"github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/kong/container"
	kongHandler "github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/kong/handler"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients"

	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/flags"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/interfaces"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
)

const (

	// SecurityBootstrapKongAdminKey is the index value for Kong within the
	// Secret Provider
	SecurityBootstrapKongAdminKey = "edgex-security-bootstrap-redis"

	// These prefixes are for "pretty" & "scoped" logging purposes only
	cmdPrefix  string = "[build-kong-admin]"
	errPrefix  string = cmdPrefix + "[error]"
	infoPrefix string = cmdPrefix + "[info]"
)

// Configure is the main entry point //TODO
func Configure(ctx context.Context,
	cancel context.CancelFunc,
	flags flags.Common) {
	startupTimer := startup.NewStartUpTimer(clients.SecurityBootstrapRedisKey)

	// CLI Argument Handling
	var dummy string

	// Create a new flag set
	flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	// Handled by bootstrap; duplicated here to prevent arg parsing errors
	flagSet.StringVar(&dummy, "confdir", "", "")

	// Look for "file_save_path" in argument list
	// flagSet.StringVar()

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	configuration := &config.ConfigurationStruct{}
	dic := di.NewContainer(di.ServiceConstructorMap{
		container.ConfigurationName: func(get di.Get) interface{} {
			return configuration
		},
	})

	kongHandler := kongHandler.NewHandler(dic)

	// bootstrap.RunAndReturnWaitGroup is needed for the underlying configuration system.
	// Conveniently, it also creates a pipeline of functions as the list of BootstrapHandler's is
	// executed in order.
	_, _, ok := bootstrap.RunAndReturnWaitGroup(
		ctx,
		cancel,
		flags,
		SecurityBootstrapKongAdminKey,
		internal.ConfigStemCore+internal.ConfigMajorVersion,
		configuration,
		nil,
		startupTimer,
		dic,
		[]interfaces.BootstrapHandler{
			// handlers.SecureProviderBootstrapHandler,
			kongHandler.SetupLoopbackAPI,
		},
	)

	if !ok {
		// had some issue(s) during bootstrapping redis
		os.Exit(1)
	}
}
