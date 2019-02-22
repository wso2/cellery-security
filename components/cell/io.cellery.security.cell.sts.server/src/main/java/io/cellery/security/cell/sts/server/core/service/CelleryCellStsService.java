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

import com.mashape.unirest.http.Unirest;
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
import io.cellery.security.cell.sts.server.core.validators.DefaultCellSTSReqValidator;
import io.cellery.security.cell.sts.server.core.validators.SelfContainedTokenValidator;
import io.cellery.security.cell.sts.server.core.validators.TokenValidator;
import org.apache.commons.lang.StringUtils;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Cellery Token Service.
 */
public class CelleryCellStsService {

    private static final String CELLERY_AUTH_SUBJECT_CLAIMS_HEADER = "x-cellery-auth-subject-claims";
    private static final String AUTHORIZATION_HEADER_NAME = "authorization";
    private static final String BEARER_HEADER_VALUE_PREFIX = "Bearer ";
    private static TokenValidator tokenValidator = new SelfContainedTokenValidator();
    private static CellSTSRequestValidator requestValidator = new DefaultCellSTSReqValidator(Collections.EMPTY_LIST);
    private static AuthorizationService authorizationService = new AuthorizationService();

    private static final Logger log = LoggerFactory.getLogger(CelleryCellStsService.class);

    private UserContextStore userContextStore;
    private UserContextStore localContextStore;

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
            boolean authenticationRequired = requestValidator.isAuthenticationRequired(cellStsRequest);
            if (!authenticationRequired) {
                return;
            }
            log.debug("Authentication is required for the request ID: {} ", requestId);
        } catch (CellSTSRequestValidationFailedException e) {
            throw new CelleryCellSTSException("Error while evaluating authentication requirement", e);
        }

        String callerCell = cellStsRequest.getSource().getCellName();
        log.debug("Caller cell : {}", callerCell);

        jwt = getUserContextJwt(cellStsRequest);
        log.debug("Incoming JWT : " + jwt);

        if (isRequestToMicroGateway(cellStsRequest)) {
            log.debug("Request to micro-gateway intercepted");
            jwtClaims = handleRequestToMicroGW(cellStsRequest, requestId, jwt);
        } else {
            jwtClaims = handleInternalRequest(cellStsRequest, requestId, jwt);
        }
        // TODO : Integrate OPA and enable authorization.
        try {
            authorizationService.authorize(cellStsRequest, jwt);
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
                cellStsRequest.getSource().getCellName(), cellStsRequest.getSource().getWorkload(),
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
            throw new CelleryCellSTSException("Error while validating locally issued security.", e);
        }
        return jwtClaims;
    }

    private JWTClaimsSet handleRequestToMicroGW(CellStsRequest cellStsRequest, String requestId, String jwt) throws
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
            throw new CelleryCellSTSException("Error while validating JWT security", e);
        }
        return jwtClaims;
    }

    private void validateInboundToken(CellStsRequest cellStsRequest, String token) throws
            TokenValidationFailureException {

        tokenValidator.validateToken(token, cellStsRequest);
    }

    private String getUserContextJwt(CellStsRequest cellStsRequest) {

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

            String stsToken = getStsToken(cellStsRequest);
            if (StringUtils.isEmpty(stsToken)) {
                throw new CelleryCellSTSException("No JWT security received from the STS endpoint: "
                        + CellStsConfiguration.getInstance().getStsEndpoint());
            }
            log.debug("Attaching jwt to outbound request : {}", stsToken);
            // Set the authorization header
            if (cellStsRequest.getRequestHeaders().get(Constants.CELLERY_AUTH_SUBJECT_HEADER) != null) {
                log.info("Found user in outgoing request");
            }
            cellStsResponse.addResponseHeader(AUTHORIZATION_HEADER_NAME, BEARER_HEADER_VALUE_PREFIX + stsToken);
        }
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
                return getTokenFromLocalSTS(jwt, CellStsUtils.getMyCellName());
            } else if (isIntraCellCall(request) && localContextStore.get(requestId) != null) {
                log.debug("Intra cell request with ID: {} from source workload {} to destination workload {} within " +
                                "cell {}", requestId, request.getSource().getWorkload(),
                        request.getDestination().getWorkload());
                return localContextStore.get(requestId);
            } else if (!isIntraCellCall(request) && localContextStore.get(requestId) != null) {
                jwt = localContextStore.get(requestId);
                return getTokenFromLocalSTS(jwt, request.getDestination().getCellName());
            } else {
                log.debug("Request initiated within cell {} to {}", request.getSource().getCellName(), request
                        .getDestination().toString());
                return getTokenFromLocalSTS(CellStsUtils.getMyCellName());
            }
        } finally {
            // do nothing
        }
    }

    private boolean isIntraCellCall(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String currentCell = CellStsUtils.getMyCellName();
        String destinationCell = cellStsRequest.getDestination().getCellName();

        return StringUtils.equals(currentCell, destinationCell);
    }

    private boolean isRequestFromMicroGateway(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String workload = cellStsRequest.getSource().getWorkload();
        if (StringUtils.isNotEmpty(workload) && workload.startsWith(CellStsUtils.getMyCellName() +
                "--gateway-deployment-")) {
            return true;
        }
        return false;
    }

    private boolean isRequestToMicroGateway(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String workload = cellStsRequest.getDestination().getWorkload();
        return (StringUtils.isNotEmpty(workload) && workload.startsWith(CellStsUtils.getMyCellName() +
                "--gateway-service"));
    }

    private String getTokenFromLocalSTS(String audience) throws CelleryCellSTSException {

        return STSTokenGenerator.generateToken(audience, CellStsUtils.getIssuerName(CellStsUtils.getMyCellName()));
    }

    private String getTokenFromLocalSTS(String jwt, String audience) throws CelleryCellSTSException {

        String token = STSTokenGenerator.generateToken(jwt, audience,
                CellStsUtils.getIssuerName(CellStsUtils.getMyCellName()));
        return token;
    }

    private void setHttpClientProperties() throws CelleryCellSTSException {

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {

                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
                // Do nothing
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                // Do nothing
            }
        }
        };

        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            throw new CelleryCellSTSException("Error while initializing SSL context");
        }

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {

                return true;
            }
        };

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        try {

            // TODO add the correct certs for hostname verification..
            Unirest.setHttpClient(HttpClients.custom()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, (x509Certificates, s)
                            -> true).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .disableRedirectHandling()
                    .build());
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            throw new CelleryCellSTSException("Error initializing the http client.", e);
        }
    }
}
