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

package io.cellery.security.cell.sts.server.core.validators;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import io.cellery.security.cell.sts.server.core.Constants;
import io.cellery.security.cell.sts.server.jwks.KeyResolverException;
import io.cellery.security.cell.sts.server.utils.CertificateUtils;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;

public class JWKSourceDataProviderTest {

    @BeforeClass
    public void setup() throws KeyResolverException, CertificateEncodingException,
            NoSuchAlgorithmException, MalformedURLException, ParseException {

        setKeysToJWKS("https://localhost:9443/oauth2/token");
        String cellName = "hr";
        System.setProperty(Constants.CELL_INSTANCE_NAME_ENV_VAR, cellName);
        System.setProperty("debug", "true");
    }

    @Test
    public void testGetInstance() throws Exception {

        Assert.assertTrue(JWKSourceDataProvider.getInstance() instanceof JWKSourceDataProvider);
    }

    @Test
    public void testGetJWKSource() throws Exception {

        Map<String, RemoteJWKSet<SecurityContext>> jwkSourceMap = JWKSourceDataProvider.getInstance().getJwkSourceMap();
        Assert.assertTrue(jwkSourceMap.size() > 0);

    }

    private RSAKey getRSAKey(RSAPublicKey publicKey, Certificate certificate) throws
            CertificateEncodingException, NoSuchAlgorithmException, ParseException {

        if (publicKey instanceof RSAPublicKey) {
            RSAKey.Builder jwk = new RSAKey.Builder((RSAPublicKey) publicKey);
            jwk.keyID(CertificateUtils.getThumbPrint(certificate));
            jwk.algorithm(JWSAlgorithm.RS256);
            jwk.keyUse(KeyUse.parse("sig"));
            return jwk.build();

        }
        return null;

    }

    @AfterClass
    public void cleanup() {

        System.getProperties().remove(Constants.CELL_INSTANCE_NAME_ENV_VAR);
        System.getProperties().remove("debug");
    }

    private void setKeysToJWKS(String jwksAddress) throws KeyResolverException,
            ParseException, CertificateEncodingException, NoSuchAlgorithmException, MalformedURLException {

        String cellName = "hr";
        System.setProperty(Constants.CELL_INSTANCE_NAME_ENV_VAR, cellName);
        System.setProperty("debug", "true");

        try {
            Map<String, RemoteJWKSet<SecurityContext>> jwkSourceMap = JWKSourceDataProvider.getInstance().
                    getJwkSourceMap();
            X509Certificate certificate = CertificateUtils.getKeyResolver().getCertificate();
            PublicKey publicKey = CertificateUtils.getKeyResolver().getPublicKey();

            JWKSetCache jwkSetCache = new DefaultJWKSetCache();
            jwkSetCache.put(new JWKSet(getRSAKey((RSAPublicKey) publicKey, certificate)));

            RemoteJWKSet<SecurityContext> securityContextRemoteJWKSet =
                    new RemoteJWKSet<>(new URL(jwksAddress), (ResourceRetriever) null,
                            jwkSetCache);

            jwkSourceMap.put(jwksAddress, securityContextRemoteJWKSet);
        } finally {
            System.getProperties().remove(Constants.CELL_INSTANCE_NAME_ENV_VAR);
            System.getProperties().remove("debug");
        }
    }

}
