/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package io.cellery.security.cell.sts.server.authorization.opa;

import com.google.gson.Gson;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.cellery.security.cell.sts.server.authorization.AuthorizationContext;
import io.cellery.security.cell.sts.server.authorization.AuthorizationFailedException;
import io.cellery.security.cell.sts.server.authorization.AuthorizationHandler;
import io.cellery.security.cell.sts.server.authorization.AuthorizationUtils;
import io.cellery.security.cell.sts.server.authorization.AuthorizeRequest;
import io.cellery.security.cell.sts.server.core.CellStsUtils;
import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Calls local OPA server and validate the request.
 */
public class OPAAuthorizationHandler implements AuthorizationHandler {

    private static final Logger log = LoggerFactory.getLogger(OPAAuthorizationHandler.class);

    @Override
    public void authorize(CellStsRequest cellStsRequest, String jwt) throws AuthorizationFailedException {

        AuthorizeRequest authorizeRequest = buildAuthorizeRequest(cellStsRequest, jwt);
        log.debug("OPA authorization handler invoked for request id: {}", authorizeRequest.getRequestId());
        // In a case of composite JWT might not be available.
        if (StringUtils.isNotEmpty(jwt)) {
            authorizeRequest.setAuthorizationContext(new OPAAuthorizationContext(authorizeRequest.
                    getAuthorizationContext().getJwt()));
        }
        Gson gson = new Gson();
        String requestString = gson.toJson(authorizeRequest);
        requestString = "{ \"input\" :" + requestString + "}";
        HttpResponse<JsonNode> apiResponse = null;
        log.info("Request to OPA server : {}", requestString);
        try {
            boolean requestToMicroGateway = CellStsUtils.isRequestToMicroGateway(cellStsRequest);
            String query = buildEndpoint(AuthorizationUtils.getOPAEndpoint(cellStsRequest, requestToMicroGateway),
                    authorizeRequest.getDestination().getWorkload(), requestToMicroGateway);
            log.info("Querying OPA from {}", query);
            apiResponse = Unirest.post(query).body(requestString).asJson();
            log.info("Response from OPA server: {}", apiResponse.getBody().toString());
            try {
                Boolean allow = apiResponse.getBody().getObject().getBoolean("result");
                if (!allow) {
                    throw new AuthorizationFailedException("Error while authorizing request. Decision found : " +
                            apiResponse.getBody().toString());
                }
            } catch (JSONException e) {
                // Ignoring since this is due to not having proper policies configured.
                log.debug("Proper policies which returns {\"result\" : boolean} are not defined for query {}",
                        query);
            }

            log.info("Authorization successfully completed for request: ", authorizeRequest.getRequestId());
        } catch (UnirestException | CelleryCellSTSException e) {
            throw new AuthorizationFailedException("Error while sending authorization request to OPA", e);
        }
    }

    private String buildEndpoint(String endpointAddress, String destinationService, boolean toMicroGateway) {

        if (toMicroGateway) {
            return endpointAddress + "/allow_access";
        }
        if (StringUtils.isEmpty(destinationService)) {
            return endpointAddress;
        }
        // "-" is a special character in OPA
        String sanitizedService = destinationService.replace("-", "_").split(":")
                [0].concat("_allow");
        return endpointAddress + "/" + sanitizedService;
    }

    private AuthorizeRequest buildAuthorizeRequest(CellStsRequest request, String jwt) throws
            AuthorizationFailedException {

        log.info("Building authorize request with jwt: " + jwt);
        AuthorizationContext authorizationContext = new AuthorizationContext(jwt);
        AuthorizeRequest authorizeRequest = new AuthorizeRequest(request, authorizationContext);
        return authorizeRequest;
    }
}
