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

package io.cellery.security.cell.sts.server.core;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;

/**
 * Token Generator used by Cell STS.
 */
public class STSTokenGenerator {

    /**
     * Generates a JWT security.
     *
     * @param incomingJWT Incoming JWT.
     * @param audience    Audience which needs to be added to JWT.
     * @param issuer      Issuer of the JWT.
     * @return JWT security as a String.
     * @throws CelleryCellSTSException
     */
    public static String generateToken(String incomingJWT, String audience, String issuer) throws CelleryCellSTSException {

        STSJWTBuilder stsjwtBuilder = new STSJWTBuilder();
        JWTClaimsSet jwtClaims = getJWTClaims(incomingJWT);
        stsjwtBuilder.subject(jwtClaims.getSubject());
        stsjwtBuilder.expiryInSeconds(1200);
        stsjwtBuilder.audience(audience);
        stsjwtBuilder.claims(jwtClaims.getClaims());
        stsjwtBuilder.issuer(issuer);
        return stsjwtBuilder.build();
    }

    /**
     * Generates a JWT security.
     *
     * @param audience Audience of the JWT to be issued.
     * @param issuer   Issuer of the JWT to be issued.
     * @return JWT security as a String.
     * @throws CelleryCellSTSException
     */
    public static String generateToken(String audience, String issuer) throws CelleryCellSTSException {

        STSJWTBuilder stsjwtBuilder = new STSJWTBuilder();
        // Default 20 mins.
        stsjwtBuilder.expiryInSeconds(1200);
        stsjwtBuilder.audience(audience);
        stsjwtBuilder.issuer(issuer);
        return stsjwtBuilder.build();
    }

    /**
     * Retrieve CalimSet of the parsed JWT.
     *
     * @param jwt JWT security.
     * @return JWTClaim Set of the input security.
     * @throws CelleryCellSTSException
     */
    public static JWTClaimsSet getJWTClaims(String jwt) throws CelleryCellSTSException {

        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new CelleryCellSTSException("Error while parsing the Signed JWT in authorization header.", e);
        }
    }
}
