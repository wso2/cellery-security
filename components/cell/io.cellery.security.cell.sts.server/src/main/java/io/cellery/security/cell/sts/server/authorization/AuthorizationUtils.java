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

package io.cellery.security.cell.sts.server.authorization;

import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.model.RequestContext;
import io.cellery.security.cell.sts.server.core.model.config.CellStsConfiguration;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.apache.commons.lang.StringUtils;

/**
 * Utilities for authorization functionality.
 */
public class AuthorizationUtils {

    /**
     * @return Endpoint address
     * @throws CelleryCellSTSException
     */
    public static String getOPAEndpoint(CellStsRequest request, boolean toMicrogateway) throws CelleryCellSTSException {

        int opaPort = 8181;
        // Running in the same pod which STS runs.
        String opaHost = "localhost";
        String opaPortCofig = System.getenv("STS_OPA_PORT");
        String opaHostConfig = System.getenv("STS_OPA_HOST");
        if (StringUtils.isNotBlank(opaPortCofig)) {
            opaPort = Integer.parseInt(opaPortCofig);
        }
        if (StringUtils.isNotEmpty(opaHostConfig)) {
            opaHost = opaHostConfig;
        }

        String opaPrefix = "data";
        if (!toMicrogateway) {
            opaPrefix = CellStsConfiguration.getInstance().getSTSOPAQueryPrefix();
            if (StringUtils.isEmpty(opaPrefix)) {
                opaPrefix = "/data/cellery/io";
            }
        }

        String baseQuery = "http://" + opaHost + ":" + opaPort + "/v1/" + opaPrefix;

        if (toMicrogateway) {
            return getGatewayContextPolicyQuery(baseQuery, request);
        } else {
            return baseQuery;
        }
    }

    public static String getGatewayContextPolicyQuery(String baseQueryPath, CellStsRequest request) {

        String context = "";
        RequestContext requestContext = request.getRequestContext();
        if (requestContext != null && StringUtils.isNotEmpty(requestContext.getPath())) {
            String[] split = requestContext.getPath().split("/");
            if (split.length > 0 && StringUtils.isNotEmpty(split[0])) {
                context = split[0];
            } else if (split.length > 1 && StringUtils.isNotEmpty(split[1])) {
                context = split[1];
            }
        }
        return baseQueryPath + "/" + context;
    }
}
