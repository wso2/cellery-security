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

import io.cellery.security.cell.sts.server.core.CellStsUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Responsible for reading keys mounted by the controller to the file system and build keys and certificates.
 */
public class FileBasedKeyResolver extends StaticKeyResolver {

    private static final Logger LOG = LoggerFactory.getLogger(FileBasedKeyResolver.class);
    private static final String SERVER_CERTS_LOCATION = "/etc/certs/";
    private static final String PRIVATE_KEY_FILE_NAME = "key.pem";
    private static final String CERTIFICATE_FILE_NAME = "cert.pem";
    private static final String START_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

    private static String privateKeyPath = SERVER_CERTS_LOCATION + PRIVATE_KEY_FILE_NAME;
    private static String publicKeyPath = SERVER_CERTS_LOCATION + CERTIFICATE_FILE_NAME;

    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static X509Certificate certificate;

    public FileBasedKeyResolver() {

        try {
            if (CellStsUtils.isRunningInDebugMode()) {
                overridePaths();
            }
            readPrivateKeyPKCS1PEM(privateKeyPath);
            readCertificate(publicKeyPath);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | CertificateException e) {
            LOG.error("Error while building keys from files", e);
        }

    }

    private void overridePaths() {

        privateKeyPath = Objects.requireNonNull(FileBasedKeyResolver.class.getClassLoader().
                getResource(PRIVATE_KEY_FILE_NAME)).getPath();
        publicKeyPath = Objects.requireNonNull(FileBasedKeyResolver.class.getClassLoader().
                getResource(CERTIFICATE_FILE_NAME)).getPath();
    }

    @Override
    public PrivateKey getPrivateKey() throws KeyResolverException {

        if (privateKey != null) {
            return privateKey;
        }
        throw new KeyResolverException("No private key found");
    }

    @Override
    public PublicKey getPublicKey() throws KeyResolverException {

        if (publicKey != null) {
            return publicKey;
        }
        throw new KeyResolverException("No public key found");
    }

    @Override
    public X509Certificate getCertificate() throws KeyResolverException {

        if (certificate != null) {
            return certificate;
        }
        throw new KeyResolverException("No certificate found");
    }

    private void readPrivateKeyPKCS1PEM(String privateKeyPath) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {

        String content = new String(
                Files.readAllBytes(Paths.get(privateKeyPath)), Charset.forName("UTF-8"));
        content = content.replaceAll("\\n", "").replace(START_RSA_PRIVATE_KEY, "")
                .replace(END_RSA_PRIVATE_KEY, "");
        byte[] bytes = Base64.getDecoder().decode(content);

        DerInputStream derReader = new DerInputStream(bytes);
        DerValue[] seq = derReader.getSequence(0);
        // skip version seq[0];
        BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCoef = seq[8].getBigInteger();

        RSAPrivateCrtKeySpec keySpec =
                new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(keySpec);
    }

    private void readCertificate(String publicKeyPath) throws CertificateException, IOException {

        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try (FileInputStream fileInputStream = new FileInputStream(publicKeyPath)) {
            certificate = (X509Certificate) fact.generateCertificate(fileInputStream);
            publicKey = certificate.getPublicKey();
        }
    }
}
