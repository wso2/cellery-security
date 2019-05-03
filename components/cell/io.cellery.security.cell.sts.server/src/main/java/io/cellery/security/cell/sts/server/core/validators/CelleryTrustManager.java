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

import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Cellery trust manager will combine the existing trust manager together with and extended trust manager which
 * trusts certificates issued to Cell STSes and other certificates which are used within cellery system.
 */
public class CelleryTrustManager implements X509TrustManager {

    public static final String TRUST_CERTS_LOCATION = "/etc/certs/trusted-certs";

    private static Log log = LogFactory.getLog(CelleryTrustManager.class);
    private X509TrustManager defaultTrustManager;
    private X509TrustManager trustManager;
    private static final String VALIDATE_SERVER_CERT = "VALIDATE_SERVER_CERT";
    private boolean validateServerCertificate;
    KeyStore keyStore;

    public CelleryTrustManager() throws CelleryCellSTSException {

        validateServerCertificate = Boolean.parseBoolean(System.getenv(VALIDATE_SERVER_CERT));
        log.info("validate server certificate is set to : " + validateServerCertificate);
        setupTrustManager();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        if (!validateServerCertificate) {
            return;
        }
        try {
            defaultTrustManager.checkServerTrusted(x509Certificates, s);
        } catch (CertificateException e) {
            trustManager.checkServerTrusted(x509Certificates, s);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

        if (!validateServerCertificate) {
            return;
        }
        try {
            defaultTrustManager.checkServerTrusted(x509Certificates, s);
        } catch (CertificateException e) {
            trustManager.checkServerTrusted(x509Certificates, s);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {

        return new X509Certificate[0];
    }

    private void setupTrustManager() throws CelleryCellSTSException {

        findDefaultTrustManager();
        setCustomTrustManager();

    }

    private void findDefaultTrustManager() throws CelleryCellSTSException {

        TrustManagerFactory trustManagerFactory = null;
        try {
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            for (int i = 0; i < trustManagers.length; i++) {
                TrustManager t = trustManagers[i];
                if (t instanceof X509TrustManager) {
                    this.defaultTrustManager = (X509TrustManager) t;
                    return;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new CelleryCellSTSException("Error while setting trust manager", e);
        }
        throw new CelleryCellSTSException("No registered trust manager found");
    }

    private void setCustomTrustManager() throws CelleryCellSTSException {

        TrustManagerFactory trustManagerFactory = null;
        try {
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            addCertificates();
            trustManagerFactory.init(keyStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            for (int i = 0; i < trustManagers.length; i++) {
                TrustManager t = trustManagers[i];
                if (t instanceof X509TrustManager) {
                    this.trustManager = (X509TrustManager) t;
                    return;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new CelleryCellSTSException("Error while setting trust manager", e);
        }
        throw new CelleryCellSTSException("No registered trust manager found");
    }

    private void addCertificates() throws CelleryCellSTSException {

        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            readCertificates();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new CelleryCellSTSException("Error while creating empty keystore", e);
        }
    }

    private List<X509Certificate> readCertificates() throws CelleryCellSTSException {

        File folder = new File(TRUST_CERTS_LOCATION);
        File[] files = folder.listFiles();
        List<X509Certificate> trustedCerts = new ArrayList<>();

        if (files != null) {
            Arrays.stream(files).forEach(file -> {

                try {
                    if (StringUtils.isNotEmpty(file.getName()) && file.getName().endsWith(".pem")) {
                        CertificateFactory fact = CertificateFactory.getInstance("X.509");
                        try (FileInputStream fileInputStream = new FileInputStream(file)) {
                            Collection<? extends Certificate> certificates = fact.generateCertificates(fileInputStream);
                            if (certificates != null) {
                                certificates.stream().forEach(certificate -> {
                                    X509Certificate x509Certificate = (X509Certificate) certificate;
                                    try {
                                        keyStore.setCertificateEntry(x509Certificate.getIssuerDN().getName(),
                                                x509Certificate);
                                    } catch (KeyStoreException e) {
                                        log.error("Error while adding certificate s {} " + certificate.toString(), e);
                                    }
                                    trustedCerts.add(x509Certificate);
                                    log.debug("Added to trust store: " + x509Certificate.getIssuerDN().getName());
                                });
                            }

                        }
                    } else {
                        log.debug("Found a non certificate file : " + file.getName());
                    }
                } catch (CertificateException | IOException e) {
                    log.error("Error while adding trusted certificte from file : " + file, e);
                }
            });
        }
        return trustedCerts;
    }
}
