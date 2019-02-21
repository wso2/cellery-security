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

package io.cellery.security.cell.sts.server.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.cellery.security.cell.sts.server.utils.CertificateUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * Builds the JWKS response in a JSON format by retrieving relevant keys.
 */
public class JWKSResponseBuilder {

    private static final Logger log = LoggerFactory.getLogger(JWKSResponseBuilder.class);

    /**
     * Builds the JSON response of JWKS.
     *
     * @param publicKey   Public Key which should be included in the jwks response.
     * @param certificate Certificate which should be in the jwks response.
     * @return JSON JWKS response.
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws ParseException
     */
    public static String buildResponse(PublicKey publicKey, Certificate certificate) throws CertificateException,
            NoSuchAlgorithmException, ParseException {

        JSONArray jwksArray = new JSONArray();
        JSONObject jwksJson = new JSONObject();

        if (publicKey instanceof RSAPublicKey) {
            RSAKey.Builder jwk = new RSAKey.Builder((RSAPublicKey) publicKey);
            jwk.keyID(CertificateUtils.getThumbPrint(certificate));
            jwk.algorithm(JWSAlgorithm.RS256);
            jwk.keyUse(KeyUse.parse("sig"));
            jwksArray.put(jwk.build().toJSONObject());
            jwksJson.put("keys", jwksArray);
            log.debug(jwksJson.toString());
        }
        return jwksJson.toString();
    }

}
