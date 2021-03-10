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
	"os"
	"testing"

	// Kong Admin Loopback API specific "config" and "container" imports
	"github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/kong/config"
	"github.com/edgexfoundry/edgex-go/internal/security/bootstrapper/kong/container"

	// Bootstrapping imports
	bootstrapper "github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/container"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/bootstrap/startup"
	"github.com/edgexfoundry/go-mod-bootstrap/v2/di"
	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"

	// Testify import
	"github.com/stretchr/testify/assert"
)

func TestHandler_SetupLoopbackAPI(t *testing.T) {

	ctx := context.Background()
	startupTimer := startup.NewStartUpTimer("random")
	configuration := &config.ConfigurationStruct{}

	dic := di.NewContainer(di.ServiceConstructorMap{
		container.ConfigurationName: func(get di.Get) interface{} {
			return configuration
		},
		bootstrapper.LoggingClientInterfaceName: func(get di.Get) interface{} {
			return logger.NewMockClient()
		},
	})

	// Create new instance of the Kong Admin API Loopback Handler
	h := NewHandler(dic)

	// Set test paths //TODO: make these in to CLI arguments
	// h.config.Paths.TemplatePath = "../testfiles/kong-admin-config.template.yml"
	// h.config.Paths.FileSavePath = "/tmp/kong.yml"

	// Remove the configuration file that is created after the test is complete
	defer os.Remove(h.config.KongPaths.FileSavePath)

	// Call our function - verify that it returns true
	actual := h.SetupLoopbackAPI(ctx, nil, startupTimer, dic)
	assert.True(t, actual)

	// Did the file get created in the path that we wanted it to be created?
	assert.FileExists(t, h.config.KongPaths.FileSavePath)

}
