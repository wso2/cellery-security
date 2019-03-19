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
 * Validate self contained acess tokens.
 */
public class SelfContainedTokenValidator implements TokenValidator {

    private JWTSignatureValidator jwtValidator = new JWKSBasedJWTValidator();
    private static final Logger log = LoggerFactory.getLogger(SelfContainedTokenValidator.class);
    private static String globalIssuer = "https://sts.cellery.io";

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

        if (jwtClaimsSet.getAudience().isEmpty()) {
            throw new TokenValidationFailureException("No audiences found in the token");
        }

        try {
            String cellAudience = CellStsUtils.getMyCellName();
            Optional<String> audienceMatch = jwtClaimsSet.getAudience().stream().filter(audience ->
                    audience.equalsIgnoreCase(cellAudience)).findAny();
            if (!audienceMatch.isPresent()) {
                throw new TokenValidationFailureException("Error while validating audience. Expected audience :" +
                        cellAudience);
            }
            log.debug("Audience validation successful");
        } catch (CelleryCellSTSException e) {
            throw new TokenValidationFailureException("Cannot infer cell name", e);
        }

    }

    private void validateIssuer(JWTClaimsSet claimsSet, CellStsRequest request) throws TokenValidationFailureException {

        if (!CellStsConfiguration.getInstance().isIssuerValidationEnabled()) {
            log.debug("Issuer validation turned off.");
            return;
        }
        String issuer = globalIssuer;
        if (StringUtils.isNotEmpty(request.getSource().getCellInstanceName())) {
            issuer = CellStsUtils.getIssuerName(request.getSource().getCellInstanceName());
        }
        String issuerInToken = claimsSet.getIssuer();
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
        if (StringUtils.isNotEmpty(sourceCell)) {
            int port = resolvePort(cellStsRequest.getSource().getCellInstanceName());
            try {
                String hostname;
                if (StringUtils.equalsIgnoreCase(sourceCell, CellStsUtils.getMyCellName())) {
                    hostname = "localhost";
                } else {
                    hostname = CellStsUtils.getIssuerName(cellStsRequest.getSource().getCellInstanceName());
                }
                jwkEndpoint = "http://" + hostname + ":" + port;
            } catch (CelleryCellSTSException e) {
                throw new TokenValidationFailureException("Error while retrieving cell name", e);
            }
        }

        log.debug("Calling JWKS endpoint: " + jwkEndpoint);
        try {
            log.debug("Validating signature of the security");
            jwtValidator.validateSignature(jwt, jwkEndpoint, jwt.getHeader().getAlgorithm().getName(), null);
        } catch (TokenValidationFailureException e) {
            throw new TokenValidationFailureException("Error while validating signature of the token", e);
        }
        log.debug("Token signature validated successfully");
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
