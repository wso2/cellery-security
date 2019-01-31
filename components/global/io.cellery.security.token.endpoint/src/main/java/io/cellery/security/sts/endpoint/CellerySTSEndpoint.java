/*
 *  Copyright (c) 2018 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package io.cellery.security.sts.endpoint;

import io.cellery.security.sts.endpoint.core.CellerySTSConstants;
import io.cellery.security.sts.endpoint.core.CellerySTSException;
import io.cellery.security.sts.endpoint.core.CellerySTSRequest;
import io.cellery.security.sts.endpoint.core.CellerySTSResponse;
import io.cellery.security.sts.endpoint.core.CellerySecureTokenService;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * This is the REST service that is exposed to get the STS security.
 */
@Path("/core")
public class CellerySTSEndpoint {

    private static final Log log = LogFactory.getLog(CellerySTSEndpoint.class);

    private CellerySecureTokenService tokenService = new CellerySecureTokenService();

    @POST
    @Path("/security")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response getStsToken(@Context HttpServletRequest request, MultivaluedMap<String, String> form) {

        CellerySTSResponse stsResponse;
        try {
            io.cellery.security.sts.endpoint.core.CellerySTSRequest cellerySTSRequest = buildStsRequest(request, form);
            stsResponse = tokenService.issueJWT(cellerySTSRequest);
        } catch (CellerySTSException e) {
            log.error("Error while issuing STS Token.", e);
            return Response.serverError().build();
        }

        // Build response.
        return Response.ok().entity(stsResponse.toJson()).build();
    }

    private CellerySTSRequest buildStsRequest(HttpServletRequest request, MultivaluedMap<String, String> form) {

        CellerySTSRequest stsRequest = new CellerySTSRequest();
        stsRequest.setSource(form.getFirst(CellerySTSConstants.CellerySTSRequest.SUBJECT));
        stsRequest.setScopes(buildValueList(form.getFirst(CellerySTSConstants.CellerySTSRequest.SCOPE)));
        stsRequest.setAudiences(buildValueList(form.getFirst(CellerySTSConstants.CellerySTSRequest.AUDIENCE)));
        stsRequest.setUserContextJwt(form.getFirst(CellerySTSConstants.CellerySTSRequest.USER_CONTEXT_JWT));
        return stsRequest;
    }

    private List<String> buildValueList(String value) {

        if (StringUtils.isNotBlank(value)) {
            value = value.trim();
            return Arrays.asList(value.split("\\s"));
        } else {
            return Collections.emptyList();
        }
    }
}

