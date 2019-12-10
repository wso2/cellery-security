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
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import static io.cellery.security.cell.sts.server.core.Constants.CELL_NAMESPACE;

/**
 * Cellery Token Service.
 */
public class CelleryCellStsService {

    private static final Logger log = LoggerFactory.getLogger(CelleryCellStsService.class);

    private static final String CELLERY_AUTH_SUBJECT_CLAIMS_HEADER = "x-cellery-auth-subject-claims";
    private static final String KNATIVE_PROBE_HEADER_NAME = "k-network-probe";
    private static final TokenValidator TOKEN_VALIDATOR = new SelfContainedTokenValidator();

    protected static final String BEARER_HEADER_VALUE_PREFIX = "Bearer ";
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

        if (cellStsRequest.getRequestHeaders().containsKey(KNATIVE_PROBE_HEADER_NAME)) {
            log.debug("Ignoring knative probe request: {}:{} ", KNATIVE_PROBE_HEADER_NAME,
                    cellStsRequest.getRequestHeaders().get(KNATIVE_PROBE_HEADER_NAME));
            return;
        }
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
        } else if (Constants.COMPOSITE_CELL_NAME.equalsIgnoreCase(CellStsUtils.getMyCellName())) {
            if (StringUtils.isEmpty(jwt)) {
                log.debug("No token found in the request. Passing through from Composite STS");
                jwtClaims = null;
                // Continues flow without aborting since we may need to block from authorization level.
            } else {
                jwtClaims = handleRequestComposite(cellStsRequest, requestId, jwt);
            }
        } else {
            jwtClaims = handleInternalRequest(cellStsRequest, requestId, jwt);
        }

        try {
            AUTHORIZATION_SERVICE.authorize(cellStsRequest, jwt);
        } catch (AuthorizationFailedException e) {
            throw new CelleryCellSTSException("Authorization failure", e);
        }
        Map<String, String> headersToSet = new HashMap<>();

        if (jwtClaims != null && StringUtils.isNotEmpty(jwtClaims.getSubject())) {
            headersToSet.put(Constants.CELLERY_AUTH_SUBJECT_HEADER, jwtClaims.getSubject());
            log.debug("Set {} to: {}", Constants.CELLERY_AUTH_SUBJECT_HEADER, jwtClaims.getSubject());
        } else {
            // Make sure workload passed header is removed.
            headersToSet.put(Constants.CELLERY_AUTH_SUBJECT_HEADER, "");
            log.debug("Subject is not available. No user context is passed.");
        }

        if (jwtClaims != null) {
            headersToSet.put(CELLERY_AUTH_SUBJECT_CLAIMS_HEADER, new PlainJWT(jwtClaims).serialize());
            log.debug("Set {} to : {}", CELLERY_AUTH_SUBJECT_CLAIMS_HEADER, new PlainJWT(jwtClaims).serialize());
        }

        cellStsResponse.addResponseHeaders(headersToSet);

    }

    private JWTClaimsSet handleRequestComposite(CellStsRequest cellStsRequest, String requestId, String jwt) throws
            CelleryCellSTSException {

        JWTClaimsSet jwtClaims;
        log.debug("Incoming request to composite STS from {}", cellStsRequest.getSource());
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

    private JWTClaimsSet handleInternalRequest(CellStsRequest cellStsRequest, String requestId, String jwt) throws
            CelleryCellSTSException {

        JWTClaimsSet jwtClaims;
        log.debug("Call from a workload to workload within cell {} ; Source workload {} ; Destination workload {}",
                cellStsRequest.getSource().getCellInstanceName(), cellStsRequest.getSource().getWorkload(),
                cellStsRequest.getDestination().getWorkload());

        try {
            if (localContextStore.get(requestId) == null) {
                log.debug("Initial entrace to cell from gateway. No cached token found.");
                validateInboundToken(cellStsRequest, jwt);
                localContextStore.put(requestId, jwt);
            } else {
                if (!StringUtils.equalsIgnoreCase(localContextStore.get(requestId), jwt)) {
                    throw new CelleryCellSTSException("Intra cell STS token is tampered.");
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

        String authzHeaderValue = CellStsUtils.getAuthorizationHeaderValue(cellStsRequest.getRequestHeaders());
        return CellStsUtils.extractJwtFromAuthzHeader(authzHeaderValue);
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
            log.info("Intercepted an outbound call to a workload:{} within Cellery. Injecting a STS token for " +
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
        cellStsResponse.addResponseHeader(Constants.CELLERY_AUTHORIZATION_HEADER_NAME,
                BEARER_HEADER_VALUE_PREFIX + stsToken);
    }

    private JWTClaimsSet extractUserClaimsFromJwt(String jwt) throws CelleryCellSTSException {

        if (StringUtils.isBlank(jwt)) {
            throw new CelleryCellSTSException("Cannot extract user context JWT from Authorization header.");
        }

        return getJWTClaims(jwt);
    }

    private JWTClaimsSet getJWTClaims(String jwt) throws CelleryCellSTSException {

        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new CelleryCellSTSException("Error while parsing the Signed JWT in authorization header.", e);
        }
    }

    private String getStsToken(CellStsRequest request) throws CelleryCellSTSException {

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
                return getTokenFromLocalSTS(CellStsUtils.getMyCellName(), request.getDestination().getWorkload());
            }
            return getTokenFromLocalSTS(jwt, CellStsUtils.getMyCellName(), request.getDestination().getWorkload());
        } else if (!CellStsUtils.isCompositeSTS() && isIntraCellCall(request) &&
                localContextStore.get(requestId) != null) {
            log.debug("Intra cell request with ID: {} from source workload {} to destination workload {} within " +
                            "cell {}", requestId, request.getSource().getWorkload(),
                    request.getDestination().getWorkload(), request.getSource().getCellInstanceName());
            return localContextStore.get(requestId);
        } else if (!CellStsUtils.isCompositeSTS() && !isIntraCellCall(request) &&
                localContextStore.get(requestId) != null) {
            log.debug("Outbound call from home cell. Building token");
            jwt = localContextStore.get(requestId);
            return getTokenFromLocalSTS(jwt, request.getDestination().getCellName(),
                    request.getDestination().getWorkload());
        } else if (CellStsUtils.isCompositeSTS() && userContextStore.get(requestId) != null) {
            String token = getTokenAsComposite(request, userContextStore.get(requestId));
            // If an initial incoming request initiates multiple outgoing requests we need to have this stored in
            userContextStore.put(requestId, token);
            return token;
        } else {
            log.debug("Request initiated within cell {} to {}", request.getSource().getCellInstanceName(), request
                    .getDestination().toString());
            String token = getUserContextJwt(request);
            if (StringUtils.isNotEmpty(token)) {
                log.debug("Found a token attached by the workload : {}", token);
                return getTokenWithWorkloadPassedBearerToken(request, token);
            }
            return getTokenFromLocalSTS(request.getDestination().getCellName(),
                    request.getDestination().getWorkload());
        }
    }

    private String getTokenWithWorkloadPassedBearerToken(CellStsRequest request, String token) throws
            CelleryCellSTSException {

        try {
            log.debug("Validating workload attached token.");
            TOKEN_VALIDATOR.validateToken(token, request);
            return getTokenFromLocalSTS(token, request.getDestination().getCellName(),
                    request.getDestination().getWorkload());
        } catch (TokenValidationFailureException e) {
            throw new CelleryCellSTSException("Error while validating workload passed token", e);
        }
    }

    private String getTokenAsComposite(CellStsRequest request, String token) throws
            CelleryCellSTSException {

        log.debug("Issuing token as composite to outbound request");
        return getTokenFromLocalSTS(token, request.getDestination().getCellName(),
                request.getDestination().getWorkload());

    }

    private boolean isIntraCellCall(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String currentCell = CellStsUtils.getMyCellName();
        String destinationCell = cellStsRequest.getDestination().getCellName();

        return StringUtils.equals(currentCell, destinationCell);
    }

    private boolean isRequestFromMicroGateway(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String workload = cellStsRequest.getSource().getWorkload();
        return StringUtils.isNotEmpty(workload) && workload.startsWith(CellStsUtils.getMyCellName() +
                "--gateway");
    }

    protected String getTokenFromLocalSTS(String audience, String destination) throws CelleryCellSTSException {

        return STSTokenGenerator.generateToken(getAudienceWithNS(audience, destination),
                CellStsUtils.getIssuerName(CellStsUtils.getMyCellName(),
                        CellStsUtils.resolveSystemVariable(CELL_NAMESPACE)), destination);
    }

    protected String getTokenFromLocalSTS(String jwt, String audience, String destination)
            throws CelleryCellSTSException {

        String token = STSTokenGenerator.generateToken(jwt, getAudienceWithNS(audience, destination),
                CellStsUtils.getIssuerName(CellStsUtils.getMyCellName(), CellStsUtils.resolveSystemVariable
                        (CELL_NAMESPACE)), destination);
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
                    new CelleryHostnameVerifier(new DefaultHostnameVerifier()));
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new CelleryCellSTSException("Error while initializing SSL context");
        }

    }

    protected String getAudienceWithNS(String rawAudience, String destination) {

        log.debug("Constructing audience for raw audience : " + rawAudience + ", and destination : " + destination);
        String namespace = CellStsUtils.getNamespaceFromAddress(destination);
        if (StringUtils.isEmpty(namespace)) {
            namespace = CellStsUtils.resolveSystemVariable(CELL_NAMESPACE);
        }
        return new StringBuilder(rawAudience).append(".").append(namespace).toString();
    }
}
