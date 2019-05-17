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

import org.junit.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class CelleryHostnameVerifierTest {

    private HostnameVerifier celleryHostnameVerifier;
    private static final String HOSTNAME_VERIFICATION_ENABLED = "ENABLE_HOSTNAME_VERIFICATION";
    HostnameVerifier defaultHostnameVerifier;

    @BeforeTest
    public void setup() {

        defaultHostnameVerifier = new HostnameVerifier() {

            @Override
            public boolean verify(String s, SSLSession sslSession) {

                return false;
            }
        };
    }

    @DataProvider(name = "validHostnameDataProvider")
    public Object[][] validHostnameDataProvider() {

        return new Object[][]{
                {"LOCALHOST"}, {"localhost"}, {"127.0.0.1"}, {"idp.cellery-system"}, {"wso2-apim"},
                {"wso2-apim-gateway"}

        };
    }

    @DataProvider(name = "invalidHostnameDataProvider")
    public Object[][] invalidHostnameDataProvider() {

        return new Object[][]{
                {"myhost.com"}, {"sts.com"}, {"10.100.23.45"}
        };
    }

    @Test(dataProvider = "validHostnameDataProvider")
    public void testVerifyWithoutEnablingHNV(String hostname) throws Exception {

        celleryHostnameVerifier = new CelleryHostnameVerifier(defaultHostnameVerifier);
        Assert.assertTrue(celleryHostnameVerifier.verify(hostname, null));

    }

    @Test(dataProvider = "invalidHostnameDataProvider")
    public void testVerifyPassWithoutEnablingHNV(String hostname) throws Exception {

        celleryHostnameVerifier = new CelleryHostnameVerifier(defaultHostnameVerifier);
        Assert.assertTrue(celleryHostnameVerifier.verify(hostname, null));
    }

    @Test(dataProvider = "validHostnameDataProvider")
    public void testVerifyEnablingHNV(String hostname) throws Exception {

        try {
            System.setProperty(HOSTNAME_VERIFICATION_ENABLED, "true");
            celleryHostnameVerifier = new CelleryHostnameVerifier(defaultHostnameVerifier);
            Assert.assertTrue(celleryHostnameVerifier.verify(hostname, null));
        } finally {
            System.getProperties().remove(HOSTNAME_VERIFICATION_ENABLED);
        }

    }

    @Test(dataProvider = "invalidHostnameDataProvider")
    public void testVerifyPassEnablingHNV(String hostname) throws Exception {

        try {
            System.setProperty(HOSTNAME_VERIFICATION_ENABLED, "true");
            celleryHostnameVerifier = new CelleryHostnameVerifier(defaultHostnameVerifier);
            Assert.assertFalse(celleryHostnameVerifier.verify(hostname, null));
        } finally {
            System.getProperties().remove(HOSTNAME_VERIFICATION_ENABLED);
        }

    }

}
