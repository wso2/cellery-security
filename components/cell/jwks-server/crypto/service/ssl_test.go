/*
 * Copyright (c) 2019 WSO2 Inc. (http:www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http:www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package service

import (
	"os"
	"testing"
)

func TestEnvFilePaths(t *testing.T) {
	err := os.Setenv(jwksPortEnvVar, "8089")
	if err != nil {
		t.Errorf("Unable to set the env var %s", jwksPortEnvVar)
	}
	if getEnvPort() != ":8089" {
		t.Errorf("Error ocured with reading the environmnt variable %s.", jwksPortEnvVar)
	}
}

func TestEnvCustomPort(t *testing.T) {
	err := os.Setenv(keyEnvVar, "/etc/cert/key.pem")
	if err != nil {
		t.Errorf("Unable to set the env var %s", keyEnvVar)
	}
	err = os.Setenv(certEnvVar, "/etc/cert/cert.pem")
	if err != nil {
		t.Errorf("Unable to set the env var %s", certEnvVar)
	}
	resolveEnvFilePaths()
	if (certFilePath != "/etc/cert/cert.pem") || (keyFilePath != "/etc/cert/key.pem") {
		t.Errorf("Expected environment variables %s and %s could not be resolved.", keyEnvVar, certEnvVar)
	}
}
