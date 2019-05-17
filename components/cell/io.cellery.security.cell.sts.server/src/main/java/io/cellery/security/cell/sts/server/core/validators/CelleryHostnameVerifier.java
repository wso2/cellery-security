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

import io.cellery.security.cell.sts.server.core.CellStsUtils;

import java.util.Arrays;
import java.util.Locale;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * This hostname verifier will verify cellery hosts and localhosts.
 */
public class CelleryHostnameVerifier implements HostnameVerifier {

    private HostnameVerifier hostnameVerifier;
    private boolean verifyHostname;
    private static final String HOSTNAME_VERIFICATION_ENABLED = "ENABLE_HOSTNAME_VERIFICATION";

    public CelleryHostnameVerifier(HostnameVerifier hostnameVerifier) {

        this.hostnameVerifier = hostnameVerifier;
        verifyHostname = Boolean.parseBoolean(CellStsUtils.resolveSystemVariable(HOSTNAME_VERIFICATION_ENABLED));
    }

    private static final String[] LOCALHOSTS =
            {"::1", "127.0.0.1", "localhost", "localhost.localdomain"};

    // These hosts are only used in dev or demo. In production proper SANs should be added to certificates.
    private static final String[] CELLERY_HOSTS = {"idp.cellery-system", "wso2-apim", "wso2-apim-gateway"};

    static boolean containsHost(String host, String[] escapedHosts) {

        host = host != null ? host.trim().toLowerCase(Locale.US) : "";
        if (host.startsWith("::1")) {
            int x = host.lastIndexOf('%');
            if (x >= 0) {
                host = host.substring(0, x);
            }
        }
        int x = Arrays.binarySearch(escapedHosts, host);
        return x >= 0;
    }

    @Override
    public boolean verify(String host, SSLSession sslSession) {

        if (!verifyHostname) {
            return true;
        }

        if (containsHost(host, LOCALHOSTS) || containsHost(host, CELLERY_HOSTS)) {
            return true;
        }
        return hostnameVerifier.verify(host, sslSession);
    }
}
