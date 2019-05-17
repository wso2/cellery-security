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

import io.cellery.security.cell.sts.server.jwks.FileBasedKeyResolver;
import io.cellery.security.cell.sts.server.jwks.KeyResolver;
import org.junit.Assert;
import org.testng.annotations.Test;

public class CertificateUtilsTest {

    @Test
    public void testGetThumbPrint() throws Exception {

        KeyResolver keyResolver = CertificateUtils.getKeyResolver();
        String thumbPrint = CertificateUtils.getThumbPrint(keyResolver.getCertificate());
        Assert.assertEquals(thumbPrint, "OTFkOTUzMGIzYTc3YjFkMmRiNmJmOTA0NTk0OGRiNjVhODBkNDllNQ");
    }

    @Test
    public void testHexify() throws Exception {

        String hexify = CertificateUtils.hexify("randomString".getBytes());
        Assert.assertNotNull(hexify);
    }

    @Test
    public void testGetKeyResolver() throws Exception {

        try {
            System.setProperty("debug", "true");
            KeyResolver keyResolver = CertificateUtils.getKeyResolver();
            Assert.assertTrue(keyResolver instanceof FileBasedKeyResolver);
        } finally {
            System.getProperties().remove("debug");
        }
    }
}
