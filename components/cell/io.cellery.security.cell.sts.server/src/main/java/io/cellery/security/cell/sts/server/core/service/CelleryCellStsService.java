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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.cellery.security.cell.sts.server.authorization.AuthorizationFailedException;
import io.cellery.security.cell.sts.server.authorization.AuthorizationService;
import io.cellery.security.cell.sts.server.core.CellStsUtils;
import io.cellery.security.cell.sts.server.core.Constants;
import io.cellery.security.cell.sts.server.core.STSTokenGenerator;
import io.cellery.security.cell.sts.server.core.context.store.UserContextStore;
import io.cellery.security.cell.sts.server.core.exception.CellSTSRequestValidationFailedException;
import io.cellery.security.cell.sts.server.core.exception.TokenValidationFailureException;
import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.model.CellStsResponse;
import io.cellery.security.cell.sts.server.core.model.RequestDestination;
import io.cellery.security.cell.sts.server.core.model.config.CellStsConfiguration;
import io.cellery.security.cell.sts.server.core.validators.CellSTSRequestValidator;
import io.cellery.security.cell.sts.server.core.validators.CelleryHostnameVerifier;
import io.cellery.security.cell.sts.server.core.validators.CelleryTrustManager;
import io.cellery.security.cell.sts.server.core.validators.DefaultCellSTSReqValidator;
import io.cellery.security.cell.sts.server.core.validators.SelfContainedTokenValidator;
import io.cellery.security.cell.sts.server.core.validators.TokenValidator;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * Cellery Token Service.
 */
public class CelleryCellStsService {

    private static final Logger log = LoggerFactory.getLogger(CelleryCellStsService.class);

    protected static final String CELLERY_AUTH_SUBJECT_CLAIMS_HEADER = "x-cellery-auth-subject-claims";
    protected static final String AUTHORIZATION_HEADER_NAME = "authorization";
    protected static final String BEARER_HEADER_VALUE_PREFIX = "Bearer ";
    protected static final TokenValidator TOKEN_VALIDATOR = new SelfContainedTokenValidator();
    protected static final CellSTSRequestValidator REQUEST_VALIDATOR = new DefaultCellSTSReqValidator();
    protected static final AuthorizationService AUTHORIZATION_SERVICE = new AuthorizationService();

    protected UserContextStore userContextStore;
    protected UserContextStore localContextStore;

    public CelleryCellStsService(UserContextStore contextStore, UserContextStore localContextStore)
            throws CelleryCellSTSException {

        this.userContextStore = contextStore;
        this.localContextStore = localContextStore;

        setHttpClientProperties();
    }

    public void handleInboundRequest(CellStsRequest cellStsRequest,
                                     CellStsResponse cellStsResponse) throws CelleryCellSTSException {

        // Extract the requestId
        String requestId = cellStsRequest.getRequestId();
        JWTClaimsSet jwtClaims;
        String jwt;

        try {
            boolean authenticationRequired = REQUEST_VALIDATOR.isAuthenticationRequired(cellStsRequest);
            if (!authenticationRequired) {
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

        if (CellStsUtils.isRequestToMicroGateway(cellStsRequest)) {
            log.debug("Request to micro-gateway intercepted");
            jwtClaims = handleRequestToMicroGW(cellStsRequest, requestId, jwt);
        } else {
            jwtClaims = handleInternalRequest(cellStsRequest, requestId, jwt);
        }
        // TODO : Integrate OPA and enable authorization.
        try {
            AUTHORIZATION_SERVICE.authorize(cellStsRequest, jwt);
        } catch (AuthorizationFailedException e) {
            throw new CelleryCellSTSException("Authorization failure", e);
        }
        Map<String, String> headersToSet = new HashMap<>();

        if (StringUtils.isNotEmpty(jwtClaims.getSubject())) {
            headersToSet.put(Constants.CELLERY_AUTH_SUBJECT_HEADER, jwtClaims.getSubject());
            log.debug("Set {} to: {}", Constants.CELLERY_AUTH_SUBJECT_HEADER, jwtClaims.getSubject());
        } else {
            log.debug("Subject is not available. No user context is passed.");
        }
        headersToSet.put(CELLERY_AUTH_SUBJECT_CLAIMS_HEADER, new PlainJWT(jwtClaims).serialize());
        log.debug("Set {} to : {}", CELLERY_AUTH_SUBJECT_CLAIMS_HEADER, new PlainJWT(jwtClaims).serialize());

        cellStsResponse.addResponseHeaders(headersToSet);

    }

    private JWTClaimsSet handleInternalRequest(CellStsRequest cellStsRequest, String requestId, String jwt) throws
            CelleryCellSTSException {

        JWTClaimsSet jwtClaims;
        log.debug("Call from a workload to workload within cell {} ; Source workload {} ; Destination workload",
                cellStsRequest.getSource().getCellInstanceName(), cellStsRequest.getSource().getWorkload(),
                cellStsRequest.getDestination().getWorkload());

        try {
            if (localContextStore.get(requestId) == null) {
                log.debug("Initial entrace to cell from gateway. No cached security found.");
                validateInboundToken(cellStsRequest, jwt);
                localContextStore.put(requestId, jwt);
            } else {
                if (!StringUtils.equalsIgnoreCase(localContextStore.get(requestId), jwt)) {
                    throw new CelleryCellSTSException("Intra cell STS security is tampered.");
                }
            }
            jwtClaims = extractUserClaimsFromJwt(jwt);
        } catch (TokenValidationFailureException e) {
            throw new CelleryCellSTSException("Error while validating locally issued token.", e);
        }
        return jwtClaims;
    }

    protected JWTClaimsSet handleRequestToMicroGW(CellStsRequest cellStsRequest, String requestId, String jwt) throws
            CelleryCellSTSException {

        JWTClaimsSet jwtClaims;
        log.debug("Incoming request to cell gateway {} from {}", CellStsUtils.getMyCellName(),
                cellStsRequest.getSource());
        try {
            log.debug("Validating incoming JWT {}", jwt);
            validateInboundToken(cellStsRequest, jwt);
            userContextStore.put(requestId, jwt);
            jwtClaims = extractUserClaimsFromJwt(jwt);

        } catch (TokenValidationFailureException e) {
            throw new CelleryCellSTSException("Error while validating JWT token", e);
        }
        return jwtClaims;
    }

    private void validateInboundToken(CellStsRequest cellStsRequest, String token) throws
            TokenValidationFailureException {

        TOKEN_VALIDATOR.validateToken(token, cellStsRequest);
    }

    protected String getUserContextJwt(CellStsRequest cellStsRequest) {

        String authzHeaderValue = getAuthorizationHeaderValue(cellStsRequest);
        return extractJwtFromAuthzHeader(authzHeaderValue);
    }

    public void handleOutboundRequest(CellStsRequest cellStsRequest,
                                      CellStsResponse cellStsResponse) throws CelleryCellSTSException {

        // First we check whether the destination of the intercepted call is within Cellery
        RequestDestination destination = cellStsRequest.getDestination();
        if (destination.isExternalToCellery()) {
            // If the intercepted call is to an external workload to Cellery we cannot do anything in the Cell STS.
            log.info("Intercepted an outbound call to a workload:{} outside Cellery. Passing the call through.",
                    destination);
        } else {
            log.info("Intercepted an outbound call to a workload:{} within Cellery. Injecting a STS security for " +
                    "authentication and user-context sharing from Cell STS.", destination);
            attachToken(cellStsRequest, cellStsResponse);
        }
    }

    protected void attachToken(CellStsRequest cellStsRequest, CellStsResponse cellStsResponse)
            throws CelleryCellSTSException {

        String stsToken = getStsToken(cellStsRequest);
        if (StringUtils.isEmpty(stsToken)) {
            throw new CelleryCellSTSException("No JWT token received from the STS endpoint: "
                    + CellStsConfiguration.getInstance().getStsEndpoint());
        }
        log.debug("Attaching jwt to outbound request : {}", stsToken);
        // Set the authorization header
        if (cellStsRequest.getRequestHeaders().get(Constants.CELLERY_AUTH_SUBJECT_HEADER) != null) {
            log.info("Found user in outgoing request");
        }
        cellStsResponse.addResponseHeader(AUTHORIZATION_HEADER_NAME, BEARER_HEADER_VALUE_PREFIX + stsToken);
    }

    private String getAuthorizationHeaderValue(CellStsRequest request) {

        return request.getRequestHeaders().get(AUTHORIZATION_HEADER_NAME);
    }

    private JWTClaimsSet extractUserClaimsFromJwt(String jwt) throws CelleryCellSTSException {

        if (StringUtils.isBlank(jwt)) {
            throw new CelleryCellSTSException("Cannot extract user context JWT from Authorization header.");
        }

        return getJWTClaims(jwt);
    }

    private String extractJwtFromAuthzHeader(String authzHeader) {

        if (StringUtils.isBlank(authzHeader)) {
            return null;
        }

        String[] split = authzHeader.split("\\s+");
        return split.length > 1 ? split[1] : null;
    }

    private JWTClaimsSet getJWTClaims(String jwt) throws CelleryCellSTSException {

        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new CelleryCellSTSException("Error while parsing the Signed JWT in authorization header.", e);
        }
    }

    private String getStsToken(CellStsRequest request) throws CelleryCellSTSException {

        try {
            // Check for a stored user context
            String requestId = request.getRequestId();
            // This is the original JWT sent to the cell gateway.
            String jwt;

            if (isRequestFromMicroGateway(request)) {
                log.debug("Request with ID: {} from micro gateway to {} workload of cell {}", requestId, request
                        .getDestination().getWorkload(), request.getDestination().getCellName());
                if (StringUtils.isNotEmpty(localContextStore.get(requestId))) {
                    log.debug("Found an already existing local token issued for same request on a different occurance");
                    return localContextStore.get(requestId);

                }
                jwt = userContextStore.get(requestId);
                if (StringUtils.isEmpty(jwt)) {
                    return getTokenFromLocalSTS(CellStsUtils.getMyCellName());
                }
                return getTokenFromLocalSTS(jwt, CellStsUtils.getMyCellName());
            } else if (isIntraCellCall(request) && localContextStore.get(requestId) != null) {
                log.debug("Intra cell request with ID: {} from source workload {} to destination workload {} within " +
                                "cell {}", requestId, request.getSource().getWorkload(),
                        request.getDestination().getWorkload());
                return localContextStore.get(requestId);
            } else if (!isIntraCellCall(request) && localContextStore.get(requestId) != null) {
                log.debug("Outbound call from home cell. Building token");
                jwt = localContextStore.get(requestId);
                return getTokenFromLocalSTS(jwt, request.getDestination().getCellName());
            } else {
                log.debug("Request initiated within cell {} to {}", request.getSource().getCellInstanceName(), request
                        .getDestination().toString());
                String token = getUserContextJwt(request);
                if (StringUtils.isNotEmpty(token)) {
                    log.debug("Found a token attached by the workload : {}", token);
                    return getTokenWithWorkloadPassedBearerToken(request, token);
                }
                return getTokenFromLocalSTS(request.getDestination().getCellName());
            }
        } finally {
            // do nothing
        }
    }

    private String getTokenWithWorkloadPassedBearerToken(CellStsRequest request, String token) throws
            CelleryCellSTSException {

        try {
            log.debug("Validating workload attached token.");
            TOKEN_VALIDATOR.validateToken(token, request);
            return getTokenFromLocalSTS(token, request.getDestination().getCellName());
        } catch (TokenValidationFailureException e) {
            throw new CelleryCellSTSException("Error while validating workload passed token", e);
        }
    }

    private boolean isIntraCellCall(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String currentCell = CellStsUtils.getMyCellName();
        String destinationCell = cellStsRequest.getDestination().getCellName();

        return StringUtils.equals(currentCell, destinationCell);
    }

    private boolean isRequestFromMicroGateway(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String workload = cellStsRequest.getSource().getWorkload();
        return StringUtils.isNotEmpty(workload) && workload.startsWith(CellStsUtils.getMyCellName() +
                "--gateway-deployment");
    }

    protected String getTokenFromLocalSTS(String audience) throws CelleryCellSTSException {

        return STSTokenGenerator.generateToken(audience, CellStsUtils.getIssuerName(CellStsUtils.getMyCellName()));
    }

    protected String getTokenFromLocalSTS(String jwt, String audience) throws CelleryCellSTSException {

        String token = STSTokenGenerator.generateToken(jwt, audience,
                CellStsUtils.getIssuerName(CellStsUtils.getMyCellName()));
        log.info("Issued a token from local STS : " + CellStsUtils.getCellImageName());
        return token;
    }

    private void setHttpClientProperties() throws CelleryCellSTSException {

        CelleryTrustManager celleryTrustManager = new CelleryTrustManager();
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[]{celleryTrustManager}, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(
                    new CelleryHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier()));
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new CelleryCellSTSException("Error while initializing SSL context");
        }

    }
}
