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
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.HashMap;

public class STSTokenGeneratorTest {

    private static final String CELL_NAME = "hr";
    private static final String DESTINATION_CELL = "destination-cell";

    @BeforeClass
    public void setup() {

        String cellName = "hr";
        System.setProperty(Constants.CELL_INSTANCE_NAME_ENV_VAR, cellName);
        System.setProperty("debug", "true");
    }

    @Test
    public void testGenerateToken() throws Exception {

        String issuer = "issuer-cell";
        String audience = "audience-cell";
        String token = STSTokenGenerator.generateToken(audience, issuer, "destination");
        JWTClaimsSet jwtClaimsSet = SignedJWT.parse(token).getJWTClaimsSet();
        Assert.assertEquals(jwtClaimsSet.getClaim("cellInstanceName"), CELL_NAME);
        Assert.assertEquals(jwtClaimsSet.getIssuer(), issuer);
        Assert.assertEquals(jwtClaimsSet.getAudience().get(0), audience);
        Assert.assertTrue(jwtClaimsSet.getExpirationTime().after(jwtClaimsSet.getIssueTime()));
    }

    @Test
    public void testGenerateTokenWithExistingJWT() throws Exception {

        String issuer = "issuer-cell";
        String audience = "audience-cell";
        String initialToken = generateToken(audience, issuer, "Alice");
        String token = STSTokenGenerator.generateToken(initialToken, audience + "-secondary",
                issuer + "-secondary", "destination");
        JWTClaimsSet jwtClaimsSet = SignedJWT.parse(token).getJWTClaimsSet();
        Assert.assertEquals(jwtClaimsSet.getClaim("cellInstanceName"), CELL_NAME);
        Assert.assertEquals(jwtClaimsSet.getIssuer(), issuer + "-secondary");
        Assert.assertEquals(jwtClaimsSet.getAudience().get(0), audience + "-secondary");
        Assert.assertTrue(jwtClaimsSet.getExpirationTime().after(jwtClaimsSet.getIssueTime()));
        Assert.assertEquals(jwtClaimsSet.getSubject(), "Alice");
    }

    @Test
    public void testGetJWTClaims() throws Exception {

    }

    @AfterClass
    public void cleanup() {

        System.getProperties().remove(Constants.CELL_INSTANCE_NAME_ENV_VAR);
        System.getProperties().remove("debug");
    }

    public static String generateToken(String audience, String issuer, String subject) throws CelleryCellSTSException {

        STSJWTBuilder stsjwtBuilder = new STSJWTBuilder();
        // Default 20 mins.
        stsjwtBuilder.expiryInSeconds(1200);
        stsjwtBuilder.audience(audience);
        stsjwtBuilder.subject(subject);
        stsjwtBuilder.issuer(issuer);
        stsjwtBuilder.claims(new HashMap<>());
        return stsjwtBuilder.build();
    }
}
