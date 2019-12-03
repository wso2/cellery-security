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
 */

package io.cellery.security.cell.sts.server.core.validators;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.cellery.security.cell.sts.server.core.CellStsUtils;
import io.cellery.security.cell.sts.server.core.Constants;
import io.cellery.security.cell.sts.server.core.exception.TokenValidationFailureException;
import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.model.config.CellStsConfiguration;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

/**
 * Validate self contained access tokens.
 */
public class SelfContainedTokenValidator implements TokenValidator {

    private JWTSignatureValidator jwtValidator = new JWKSBasedJWTValidator();
    private static final Logger log = LoggerFactory.getLogger(SelfContainedTokenValidator.class);
    private static String globalIssuer = "https://sts.cellery.io";
    private static final String compositeIssuer = CellStsUtils.getIssuerName(Constants.COMPOSITE_CELL_NAME,
            Constants.SYSTEM_NAMESPACE);
    public static final String KNATIVE_ACTIVATOR_WORKLOAD_REGEX = "^activator-.*\\.knative-serving$";

    /**
     * Validates a self contained access security.
     *
     * @param token          Incoming security. JWT to be validated.
     * @param cellStsRequest Request which reaches cell STS.
     * @throws TokenValidationFailureException TokenValidationFailureException.
     */
    @Override
    public void validateToken(String token, CellStsRequest cellStsRequest) throws TokenValidationFailureException {

        if (StringUtils.isEmpty(token)) {
            throw new TokenValidationFailureException("No token found in the request.");
        }
        try {
            log.debug("Validating token: {}", token);
            SignedJWT parsedJWT = SignedJWT.parse(token);
            JWTClaimsSet jwtClaimsSet = parsedJWT.getJWTClaimsSet();
            validateIssuer(jwtClaimsSet, cellStsRequest);
            validateAudience(jwtClaimsSet, cellStsRequest);
            validateExpiry(jwtClaimsSet);
            validateSignature(parsedJWT, cellStsRequest);
        } catch (ParseException e) {
            throw new TokenValidationFailureException("Error while parsing JWT: " + token, e);
        }
    }

    private void validateExpiry(JWTClaimsSet jwtClaimsSet) throws TokenValidationFailureException {

        // Validating expiry is a part of signature validation.
        // validation.
        if (!CellStsConfiguration.getInstance().isSignatureValidationEnabled()) {
            log.debug("Issuer validation turned off.");
            return;
        }
        if (jwtClaimsSet.getExpirationTime().before(new Date(System.currentTimeMillis()))) {
            throw new TokenValidationFailureException("Token has expired. Expiry time: " + jwtClaimsSet
                    .getExpirationTime());
        }
        log.debug("Token life time is valid, expiry time: {}", jwtClaimsSet.getExpirationTime());
    }

    private void validateAudience(JWTClaimsSet jwtClaimsSet, CellStsRequest cellStsRequest) throws
            TokenValidationFailureException {

        if (!CellStsConfiguration.getInstance().isAudienceValidationEnabled()) {
            log.debug("Audience validation turned off.");
            return;
        }

        if (jwtClaimsSet.getAudience().isEmpty() && !CellStsUtils.isCompositeSTS()) {
            throw new TokenValidationFailureException("No audiences found in the token");
        }

        try {
            String cellAudience = CellStsUtils.getMyCellName();
            Optional<String> audienceMatch = jwtClaimsSet.getAudience().stream().filter(audience ->
                    audience.equalsIgnoreCase(cellAudience)).findAny();
            if (!audienceMatch.isPresent() && !isReqAddressedToComposite(jwtClaimsSet, cellStsRequest)) {
                throw new TokenValidationFailureException("Error while validating audience. Expected audience :" +
                        cellAudience);
            }
            log.debug("Audience validation successful");
        } catch (CelleryCellSTSException e) {
            throw new TokenValidationFailureException("Cannot infer cell name", e);
        }

    }

    private boolean isReqAddressedToComposite(JWTClaimsSet claimsSet, CellStsRequest request) {

        String destination = (String) claimsSet.getClaim(Constants.DESTINATION);
        log.debug("Destination of the jwt is : " + destination);
        log.debug("Destination derived from request : " + request.getDestination().getWorkload());
        if (!CellStsUtils.isCompositeSTS()) {
            log.debug("Not composite STS. Hence audience has to be validated with proper cell name.");
            return false;
        }
        log.debug("Composite STS checking whether the incoming jwt is addressed towards composite");

        if (StringUtils.equals(destination, request.getDestination().getWorkload())) {
            // Request has reached to the intended service in composite. Hence not validating audience
            log.debug("Destination found in the token matches with the actual destination. Hence audience is valid " +
                    "for composite.");
            return true;
        }
        if (StringUtils.isBlank(destination) && globalIssuer.equalsIgnoreCase(claimsSet.getIssuer())) {
            // Assumes the request is from global gateway.
            log.debug("Destination is not available and the issuer is global. Hence audience is considered as valid " +
                    "by composite STS.");
            return true;
        }

        log.debug("Request is not addressed towards composite STS");
        return false;
    }

    private void validateIssuer(JWTClaimsSet claimsSet, CellStsRequest request) throws TokenValidationFailureException {

        if (!CellStsConfiguration.getInstance().isIssuerValidationEnabled()) {
            log.debug("Issuer validation turned off.");
            return;
        }
        String issuer = globalIssuer;
        String workload = request.getSource().getWorkload();
        String issuerInToken = claimsSet.getIssuer();

        if (StringUtils.isNotEmpty(request.getSource().getCellInstanceName())) {
            String sourceSTSNamespace = CellStsUtils.getNamespaceFromAddress(request.getSource().getWorkload());
            if (StringUtils.isNotEmpty(issuerInToken) && compositeIssuer.equalsIgnoreCase(issuerInToken)) {
                sourceSTSNamespace = Constants.SYSTEM_NAMESPACE;
                log.debug("Composite issuer found. Hence changing source issuer ns to " + Constants.SYSTEM_NAMESPACE);
            }
            issuer = CellStsUtils.getIssuerName(request.getSource().getCellInstanceName(),
                    sourceSTSNamespace);
        } else if (StringUtils.isNotEmpty(workload) && workload.matches(KNATIVE_ACTIVATOR_WORKLOAD_REGEX)) {
            try {
                log.debug("Request is received from the knative activator. Setting issuer to this cell");
                issuer = CellStsUtils.getIssuerName(CellStsUtils.getMyCellName(),
                        CellStsUtils.getNamespaceFromAddress(request.getSource().getWorkload()));
            } catch (CelleryCellSTSException e) {
                throw new TokenValidationFailureException("Cannot infer the issuer", e);
            }
        }
        if (StringUtils.isEmpty(issuerInToken)) {
            throw new TokenValidationFailureException("No issuer found in the JWT");
        }

        String gatewayIssuer = CellStsUtils.getGatewayIssuer(request.getSource().getCellInstanceName());

        // In web cells the issuer will be the gateway of it's own cell.
        if (StringUtils.equalsIgnoreCase(issuerInToken, gatewayIssuer)) {
            return;
        }

        if (!StringUtils.equalsIgnoreCase(issuerInToken, issuer)) {
            throw new TokenValidationFailureException("Issuer validation failed. Expected issuer : " + issuer + ". " +
                    "Received issuer: " + issuerInToken);
        }
        log.debug("Issuer validated successfully. Issuer : {}", issuer);
    }

    private void validateSignature(JWT jwt, CellStsRequest cellStsRequest) throws TokenValidationFailureException {

        if (!CellStsConfiguration.getInstance().isSignatureValidationEnabled()) {
            log.debug("Signature validation turned off.");
            return;
        }

        String jwkEndpoint = CellStsConfiguration.getInstance().getGlobalJWKEndpoint();
        String sourceCell = cellStsRequest.getSource().getCellInstanceName();
        String workload = cellStsRequest.getSource().getWorkload();

        if (StringUtils.isEmpty(sourceCell) && StringUtils.isNotEmpty(workload)
                && workload.matches(KNATIVE_ACTIVATOR_WORKLOAD_REGEX)) {
            try {
                log.debug("Request is received from the knative activator. Setting source cell to this cell");
                sourceCell = CellStsUtils.getMyCellName();
            } catch (CelleryCellSTSException e) {
                throw new TokenValidationFailureException("Cannot infer the source cell name", e);
            }
        }

        if (StringUtils.isNotEmpty(sourceCell)) {
            int port = resolvePort(sourceCell);
            try {
                JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
                String hostname;
                if (StringUtils.equalsIgnoreCase(sourceCell, CellStsUtils.getMyCellName())) {
                    hostname = "localhost";
                } else if (isTokenFromComposite(jwtClaimsSet.getStringClaim(Constants.DESTINATION),
                        cellStsRequest.getDestination().getWorkload(), jwtClaimsSet.getIssuer())) {
                    log.debug("Validating token issued by composite cell");
                    hostname = jwtClaimsSet.getIssuer();
                } else {
                    log.debug("Deriving hostname from source and source workload ns" +
                            CellStsUtils.getNamespaceFromAddress(cellStsRequest.getSource().getWorkload()));
                    hostname = CellStsUtils.getIssuerName(sourceCell,
                            CellStsUtils.getNamespaceFromAddress(cellStsRequest.getSource().getWorkload()));
                }

                jwkEndpoint = "https://" + hostname + ":" + port;
            } catch (CelleryCellSTSException | ParseException e) {
                throw new TokenValidationFailureException("Error while retrieving cell name", e);
            }
        }

        log.debug("Calling JWKS endpoint: " + jwkEndpoint);
        try {
            log.debug("Validating signature of the token");
            jwtValidator.validateSignature(jwt, jwkEndpoint, jwt.getHeader().getAlgorithm().getName(), null);
        } catch (TokenValidationFailureException e) {
            throw new TokenValidationFailureException("Error while validating signature of the token", e);
        }
        log.debug("Token signature validated successfully");
    }

    private boolean isTokenFromComposite(String destinationFromToken, String destinationFromRequest, String issuer) {

        log.debug("Asserting whether the token is issued by composite, Issuer :" + issuer + ". Destination from req :" +
                " " + destinationFromRequest + ", destination from token : " + destinationFromToken);
        if (CellStsUtils.getIssuerName(Constants.COMPOSITE_CELL_NAME, Constants.SYSTEM_NAMESPACE).
                equalsIgnoreCase(issuer) && StringUtils.equals(destinationFromRequest, destinationFromToken)) {
            return true;
        }
        return false;
    }

    private int resolvePort(String cellName) {

        int port = 8090;
        // Keep this commented code for the easiness of testing.
//        switch (cellName) {
//            case "hr":
//                port = 8090;
//                break;
//            case "employee":
//                port = 8091;
//                break;
//            case "stock-options":
//                port = 8092;
//                break;
//        }
        return port;
    }
}
