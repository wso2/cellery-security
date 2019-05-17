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
import io.cellery.security.cell.sts.server.core.Constants;
import io.cellery.security.cell.sts.server.core.exception.CellSTSRequestValidationFailedException;
import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.model.RequestContext;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.file.Paths;
import java.util.HashMap;

public class DefaultCellSTSReqValidatorTest {

    DefaultCellSTSReqValidator defaultCellSTSReqValidator = new DefaultCellSTSReqValidator();
    String resourceLocation = Paths.get(System.getProperty("user.dir"), "src", "test",
            "resources").toString();
    private static final String UNSECURED_PATHS_ENV_VARIABLE = "UNSECURED_CONTEXTS_CONF_PATH";

    @Test(expectedExceptions = CellSTSRequestValidationFailedException.class)
    public void testValidate() throws Exception {

        CellStsRequest.CellStsRequestBuilder cellStsRequestBuilder = new CellStsRequest.CellStsRequestBuilder();
        HashMap headers = new HashMap();
        headers.put(Constants.CELLERY_AUTH_SUBJECT_HEADER, "Alice");
        cellStsRequestBuilder.setRequestHeaders(headers);
        defaultCellSTSReqValidator.validate(cellStsRequestBuilder.build());
    }

    @Test
    public void testValidateWithException() throws Exception {

        CellStsRequest.CellStsRequestBuilder cellStsRequestBuilder = new CellStsRequest.CellStsRequestBuilder();
        HashMap headers = new HashMap();
        cellStsRequestBuilder.setRequestHeaders(headers);
        defaultCellSTSReqValidator.validate(cellStsRequestBuilder.build());
    }

    @DataProvider(name = "unsecuredPathDataProvider")
    public Object[][] unsecuredPathDataProvider() {

        return new Object[][]{
                {"/hello-world", false}, {"undefined/path", true},
                {"unsecured-path", false}, {"/secured/path", true},
        };
    }

    @Test(dataProvider = "unsecuredPathDataProvider")
    public void testIsAuthenticationRequired(String inputPath, boolean isUnsecured) throws Exception {

        try {
            CellStsRequest.CellStsRequestBuilder cellStsRequestBuilder = new CellStsRequest.CellStsRequestBuilder();
            RequestContext requestContext = new RequestContext();
            requestContext.setPath(inputPath);
            cellStsRequestBuilder.setRequestContext(requestContext);
            System.setProperty(UNSECURED_PATHS_ENV_VARIABLE, resourceLocation + "/unsecured-paths.json");
            CellStsUtils.readUnsecuredContexts();
            Assert.assertEquals(defaultCellSTSReqValidator.isAuthenticationRequired(cellStsRequestBuilder.build()),
                    isUnsecured);
        } finally {
            System.getProperties().remove(UNSECURED_PATHS_ENV_VARIABLE);
        }
    }
}
