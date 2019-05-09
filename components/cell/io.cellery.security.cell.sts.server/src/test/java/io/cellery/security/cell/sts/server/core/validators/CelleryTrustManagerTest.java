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

import org.junit.Before;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class CelleryTrustManagerTest {

    private static final String VALIDATE_SERVER_CERT = "VALIDATE_SERVER_CERT";
    String resourceLocation = Paths.get(System.getProperty("user.dir"), "src", "test",
            "resources").toString();
    X509Certificate certificate;
    String trustedCertsLocation;

    @Before
    public void setup() throws Exception {

        trustedCertsLocation = resourceLocation + "/trustedCerts";
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try (FileInputStream fileInputStream = new FileInputStream(trustedCertsLocation)) {
            certificate = (X509Certificate) fact.generateCertificate(fileInputStream);
        }
    }

    @Test
    public void testCheckServerTrustedWithoutEnableTM() throws Exception {

        X509TrustManager celleryTrustManager = new CelleryTrustManager();
        celleryTrustManager.checkServerTrusted(null, null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testCheckServerTrustedEnableTM() throws Exception {

        try {
            System.setProperty(VALIDATE_SERVER_CERT, "true");
            X509TrustManager celleryTrustManager = new CelleryTrustManager();
            celleryTrustManager.checkServerTrusted(null, null);
        } finally {
            System.getProperties().remove(VALIDATE_SERVER_CERT);
        }

    }
}
