/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package io.cellery.security.cell.sts.server.core.service;

import io.cellery.security.cell.sts.server.authorization.AuthorizationFailedException;
import io.cellery.security.cell.sts.server.core.CellStsUtils;
import io.cellery.security.cell.sts.server.core.Constants;
import io.cellery.security.cell.sts.server.core.context.store.UserContextStore;
import io.cellery.security.cell.sts.server.core.exception.CellSTSRequestValidationFailedException;
import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.model.CellStsResponse;
import io.cellery.security.cell.sts.server.core.model.config.CellStsConfiguration;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * STS service to serve traffic intercepted by the gateway inbound sidecar.
 */
public class CelleryGWSTSService extends CelleryCellStsService {

    private static final Logger log = LoggerFactory.getLogger(CelleryGWSTSService.class);

    public CelleryGWSTSService(UserContextStore contextStore, UserContextStore localContextStore) throws
            CelleryCellSTSException {

        super(contextStore, localContextStore);
    }

    public void handleInboundRequest(CellStsRequest cellStsRequest,
                                     CellStsResponse cellStsResponse) throws CelleryCellSTSException {

        // Extract the requestId
        String requestId = cellStsRequest.getRequestId();
        String jwt;

        if (log.isDebugEnabled()) {
            log.debug("Request reached gateway sidecar.");
        }
        try {
            boolean authenticationRequired = REQUEST_VALIDATOR.isAuthenticationRequired(cellStsRequest);
            if (!authenticationRequired) {
                attachToken(cellStsRequest, cellStsResponse);
                return;
            }
            log.debug("Authentication is required for the request ID: {} ", requestId);
        } catch (CellSTSRequestValidationFailedException e) {
            throw new CelleryCellSTSException("Error while evaluating authentication requirement", e);
        }

        String callerCell = cellStsRequest.getSource().getCellInstanceName();
        log.debug("Caller cell : {}", callerCell);

        jwt = getUserContextJwt(cellStsRequest);
        log.debug("Incoming JWT : " + jwt);

        handleRequestToMicroGW(cellStsRequest, requestId, jwt);

        try {
            AUTHORIZATION_SERVICE.authorize(cellStsRequest, jwt);
        } catch (AuthorizationFailedException e) {
            throw new CelleryCellSTSException("Authorization failure", e);
        }
        attachToken(cellStsRequest, cellStsResponse);
        log.info("Gateway request processing ended successfully for request: {}", requestId);
    }

    protected void attachToken(CellStsRequest cellStsRequest, CellStsResponse cellStsResponse)
            throws CelleryCellSTSException {

        String stsToken = exchangeToInternalToken(cellStsRequest);
        if (StringUtils.isEmpty(stsToken)) {
            throw new CelleryCellSTSException("No JWT token received from the STS endpoint: "
                    + CellStsConfiguration.getInstance().getStsEndpoint());
        }
        log.debug("Attaching jwt to gateway request : {}", stsToken);
        // Set the authorization header
        if (cellStsRequest.getRequestHeaders().get(Constants.CELLERY_AUTH_SUBJECT_HEADER) != null) {
            log.info("Found user in outgoing request");
        }
        cellStsResponse.addResponseHeader(Constants.CELLERY_AUTHORIZATION_HEADER_NAME,
                BEARER_HEADER_VALUE_PREFIX + stsToken);
    }

    protected String exchangeToInternalToken(CellStsRequest request) throws CelleryCellSTSException {

        String requestId = request.getRequestId();
        // This is the original JWT sent to the cell gateway.
        String jwt;

        log.debug("Request with ID: {} to micro gateway from {}", requestId, request.getSource());
        if (StringUtils.isNotEmpty(localContextStore.get(requestId))) {
            log.debug("Found an already existing local token issued for same request on a different occurance");
            return localContextStore.get(requestId);
        }
        jwt = userContextStore.get(requestId);
        if (StringUtils.isEmpty(jwt)) {
            return getTokenFromLocalSTS(CellStsUtils.getMyCellName(), request.getDestination().getWorkload());
        }
        // Remove from cache since this is no longer required after building local jwt.
        userContextStore.remove(requestId);
        return getTokenFromLocalSTS(jwt, CellStsUtils.getMyCellName(), request.getDestination().getWorkload());
    }
}
