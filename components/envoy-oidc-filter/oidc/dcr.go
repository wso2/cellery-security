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

package oidc

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	contentTypeHeader = "Content-Type"
	contentTypeJson   = "application/json"
)

func isDcrRequired(c *Config) bool {
	if !isEmpty(c.ClientID) && !isEmpty(c.ClientSecret) {
		// client id and client secret provided, DCR not required
		return false
	}
	return true
}

func dcr(c *Config) (string, string, error) {
	values := map[string]interface{}{"client_name": c.ClientID, "grant_types": []string{"password",
		"authorization_code", "implicit"}, "ext_param_client_id": c.ClientID, "redirect_uris": []string{c.RedirectURL}}

	payload, err := json.Marshal(values)
	if err != nil {
		return "", "", err
	}
	log.Printf("DCR payload: " + string(payload))

	req, err := http.NewRequest("POST", c.DcrEP, bytes.NewBuffer(payload))
	if err != nil {
		return "", "", err
	}
	req.SetBasicAuth(c.DcrUser, c.DcrPassword)
	req.Header.Set(contentTypeHeader, contentTypeJson)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var clientSecret string
	if (resp.StatusCode != 201) {
		if resp.StatusCode == 400 {
			var errResp dcrErrorResponse
			err = json.Unmarshal(body, &errResp)
			if err != nil {
				return "", "", err
			}
			// check if this is due to oauth application already exist error
			if errResp.Error == "invalid_client_metadata" {
				log.Printf("Bad request while attempting DCR: %v", errResp.ErrorDescription)
				// try to retrieve if exists
				clientSecret, err = getClientSecret(c)
				if err != nil {
					return "", "", err
				}
			}
		} else {
			log.Printf("Error occurred while attempting DCR: %+v" + string(body))
		}
	} else {
		var successResp dcrSuccessResponse
		err = json.Unmarshal(body, &successResp)
		if err != nil {
			return "", "", err
		}
		clientSecret = successResp.ClientSecret
	}
	return c.ClientID, clientSecret, nil
}

func getClientSecret(c *Config) (string, error) {
	req, err := http.NewRequest("GET", strings.TrimSuffix(c.DcrEP, "/")+"?client_name="+
		c.ClientID, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.DcrUser, c.DcrPassword)
	req.Header.Set(contentTypeHeader, contentTypeJson)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var clientSecret string
	if resp.StatusCode != 200 {
		// error
		return "", errors.Errorf("Error occurred while retrieving oauth application %v, error: %+v",
			c.ClientID, body)
	} else {
		var successResp dcrSuccessResponse
		err = json.Unmarshal(body, &successResp)
		if err != nil {
			return "", err
		}
		log.Printf("Retrieved Oauth app with client name: %v, client id %v", successResp.ClientName,
			successResp.ClientId)
		clientSecret = successResp.ClientSecret
	}
	return clientSecret, nil
}
