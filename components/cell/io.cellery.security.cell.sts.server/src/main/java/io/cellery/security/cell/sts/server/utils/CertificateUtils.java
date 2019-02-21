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

package io.cellery.security.cell.sts.server.utils;

import io.cellery.security.cell.sts.server.core.CellStsUtils;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import io.cellery.security.cell.sts.server.jwks.KeyResolver;
import io.cellery.security.cell.sts.server.jwks.KeyResolverException;
import io.cellery.security.cell.sts.server.jwks.SelfSignedKeyResolver;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

/**
 * Utilities used for certificate generation and parsing.
 */
public class CertificateUtils {

    private static final Logger log = LoggerFactory.getLogger(CertificateUtils.class);
    private static KeyResolver keyResolver;

    static {
        try {
            keyResolver = new SelfSignedKeyResolver(CellStsUtils.getMyCellName());
        } catch (KeyResolverException | CelleryCellSTSException e) {
            log.error("Error while initiating key resolver", e);
        }
    }

    public static String getThumbPrint(Certificate certificate) throws NoSuchAlgorithmException,
            CertificateEncodingException {

        MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
        byte[] der = certificate.getEncoded();
        digestValue.update(der);
        byte[] digestInBytes = digestValue.digest();
        String publicCertThumbprint = hexify(digestInBytes);
        return new String((new Base64(0, (byte[]) null, true)).
                encode(publicCertThumbprint.getBytes(Charset.forName("UTF-8"))), Charset.forName("UTF-8"));
    }

    public static String hexify(byte[] bytes) {

        if (bytes == null) {
            String errorMsg = "Invalid byte array: 'NULL'";
            throw new IllegalArgumentException(errorMsg);
        } else {
            char[] hexDigits = new char[]{'0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            StringBuilder buf = new StringBuilder(bytes.length * 2);

            for (int i = 0; i < bytes.length; ++i) {
                buf.append(hexDigits[(bytes[i] & 240) >> 4]);
                buf.append(hexDigits[bytes[i] & 15]);
            }

            return buf.toString();
        }
    }

    public static KeyResolver getKeyResolver() {

        return keyResolver;
    }
}
