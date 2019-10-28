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

package io.cellery.security.cell.sts.server.core;

import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.model.RequestDestination;
import io.cellery.security.cell.sts.server.core.model.config.CellStsConfiguration;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.file.Paths;
import java.util.List;

public class CellStsUtilsTest {

    private static final String STS_CONFIG_PATH_ENV_VARIABLE = "CONF_PATH";
    private static final String UNSECURED_PATHS_ENV_VARIABLE = "UNSECURED_CONTEXTS_CONF_PATH";
    String resourceLocation = Paths.get(System.getProperty("user.dir"), "src", "test",
            "resources").toString();

    @Test
    public void testGetMyCellName() throws Exception {

        try {
            String cellName = "hr";
            System.setProperty(Constants.CELL_INSTANCE_NAME_ENV_VAR, cellName);
            Assert.assertEquals(CellStsUtils.getMyCellName(), cellName, "Expected cell name not found");
        } finally {
            System.getProperties().remove(Constants.CELL_INSTANCE_NAME_ENV_VAR);
        }

    }

    @Test(expectedExceptions = CelleryCellSTSException.class)
    public void testGetMyCellNameError() throws Exception {

        Assert.assertEquals(CellStsUtils.getMyCellName(), "hr", "No error thrown even if cell " +
                "name not set");
    }

    @Test
    public void testGetCellImageName() throws Exception {

        try {
            String imageName = "hr-image";
            System.setProperty(Constants.CELL_IMAGE_NAME_ENV_VAR, imageName);
            Assert.assertEquals(CellStsUtils.getCellImageName(), imageName, "Expected image name not found");
        } finally {
            System.getProperties().remove(Constants.CELL_IMAGE_NAME_ENV_VAR);
        }

    }

    @Test
    public void testGetCellVersion() throws Exception {

        try {
            String cellVersion = "2.1.1";
            System.setProperty(Constants.CELL_VERSION_ENV_VAR, cellVersion);
            Assert.assertEquals(CellStsUtils.getCellVersion(), cellVersion, "Expected image name not found");
        } finally {
            System.getProperties().remove(Constants.CELL_VERSION_ENV_VAR);
        }
    }

    @DataProvider(name = "workloadDataProvider")
    public Object[][] workloadDataProvider() {

        return new Object[][]{
                {"LOCALHOST", false}, {"hr--gateway-service", true},
                {"hr", false}, {"hr--gateway", false},
                {"--something", false}, {"hr--gateway-service-asdfasdad-dep-adsfa", true},

        };
    }

    @Test(dataProvider = "workloadDataProvider")
    public void testIsRequestToMicroGateway(String workload, boolean result) throws Exception {

        try {
            String cellName = "hr";
            System.setProperty(Constants.CELL_INSTANCE_NAME_ENV_VAR, cellName);
            RequestDestination requestDestination =
                    getRequestDestination(cellName, workload, false);
            CellStsRequest.CellStsRequestBuilder cellStsRequestBuilder = new CellStsRequest.CellStsRequestBuilder();
            cellStsRequestBuilder.setDestination(requestDestination);
            CellStsRequest cellStsRequest = cellStsRequestBuilder.build();

            Assert.assertEquals(CellStsUtils.isRequestToMicroGateway(cellStsRequest), result);
        } finally {
            System.getProperties().remove(Constants.CELL_INSTANCE_NAME_ENV_VAR);
        }

    }

    private RequestDestination getRequestDestination(String cellName, String workloadName,
                                                     boolean isExternalToCellery) {

        RequestDestination.RequestDestinationBuilder requestDestinationBuilder =
                new RequestDestination.RequestDestinationBuilder();
        requestDestinationBuilder.setCellName(cellName);
        requestDestinationBuilder.setWorkload(workloadName);
        requestDestinationBuilder.setExternalToCellery(isExternalToCellery);
        return requestDestinationBuilder.build();
    }

    @DataProvider(name = "workloadDataProviderToGW")
    public Object[][] workloadDataProviderToGW() {

        return new Object[][]{
                {"LOCALHOST"}, {"hr--gateway-service"},
                {"hr"}, {"hr--gateway"},
                {"--something"}, {"hr--gateway-service-asdfasdad-dep-adsfa"},
        };
    }

    @Test(dataProvider = "workloadDataProviderToGW")
    public void testIsWorkloadExternalToCellery(String workload) throws Exception {

        try {
            String cellName = "hr";
            System.setProperty(Constants.CELL_INSTANCE_NAME_ENV_VAR, cellName);
            RequestDestination requestDestination =
                    getRequestDestination(cellName, workload, false);
            CellStsRequest.CellStsRequestBuilder cellStsRequestBuilder = new CellStsRequest.CellStsRequestBuilder();
            cellStsRequestBuilder.setDestination(requestDestination);
            cellStsRequestBuilder.setIsGatewayIncomingRequest(true);
            CellStsRequest cellStsRequest = cellStsRequestBuilder.build();

            Assert.assertTrue(CellStsUtils.isRequestToMicroGateway(cellStsRequest));
        } finally {
            System.getProperties().remove(Constants.CELL_INSTANCE_NAME_ENV_VAR);
        }

    }

    @Test
    public void testGetIssuerName() throws Exception {

        Assert.assertEquals(CellStsUtils.getIssuerName("hr"), new StringBuilder("hr")
                .append(Constants.STS_SERVICE).append(".").append(Constants.DEFAULT_NAMESPACE).toString());
    }

    @Test
    public void testGetGatewayIssuer() throws Exception {

        Assert.assertEquals(CellStsUtils.getGatewayIssuer("hr"), "hr--gateway");
    }

    @Test
    public void testGetConfigFilePath() throws Exception {

        try {
            String configPath = "/config/file/directory";
            System.setProperty(STS_CONFIG_PATH_ENV_VARIABLE, configPath);
            Assert.assertEquals(CellStsUtils.getConfigFilePath(), configPath);
        } finally {
            System.getProperties().remove(STS_CONFIG_PATH_ENV_VARIABLE);
        }
    }

    @Test
    public void testGetUnsecuredPathsConfigPath() throws Exception {

        try {
            String configPath = "/config/file/directory";
            System.setProperty(UNSECURED_PATHS_ENV_VARIABLE, configPath);
            Assert.assertEquals(CellStsUtils.getUnsecuredPathsConfigPath(), configPath);
        } finally {
            System.getProperties().remove(UNSECURED_PATHS_ENV_VARIABLE);
        }
    }

    @Test
    public void testBuildCellStsConfiguration() throws Exception {

        try {
            String cellName = "hr";
            System.setProperty(Constants.CELL_INSTANCE_NAME_ENV_VAR, cellName);
            System.setProperty(STS_CONFIG_PATH_ENV_VARIABLE, resourceLocation + "/sts.json");
            CellStsUtils.buildCellStsConfiguration();
            Assert.assertEquals(CellStsConfiguration.getInstance().getGlobalJWKEndpoint(),
                    "https://localhost:9443/oauth2/jwks");
            Assert.assertEquals(CellStsConfiguration.getInstance().getCellName(),
                    cellName);
            Assert.assertEquals(CellStsConfiguration.getInstance().getSTSOPAQueryPrefix(), "data/cellery/io");
            Assert.assertEquals(CellStsConfiguration.getInstance().isAudienceValidationEnabled(), true);
            Assert.assertEquals(CellStsConfiguration.getInstance().getUsername(), "admin");
            Assert.assertEquals(CellStsConfiguration.getInstance().getPassword(), "admin123");
            Assert.assertEquals(CellStsConfiguration.getInstance().isAuthorizationEnabled(), true);
            Assert.assertEquals(CellStsConfiguration.getInstance().isIssuerValidationEnabled(), true);

        } finally {
            System.getProperties().remove(STS_CONFIG_PATH_ENV_VARIABLE);
            System.getProperties().remove(UNSECURED_PATHS_ENV_VARIABLE);
        }

    }

    @Test
    public void testReadUnsecuredContexts() throws Exception {

        try {
            System.setProperty(UNSECURED_PATHS_ENV_VARIABLE, resourceLocation + "/unsecured-paths.json");
            CellStsUtils.readUnsecuredContexts();
            List<String> unsecuredAPIS = CellStsConfiguration.getInstance().getUnsecuredAPIS();
            Assert.assertEquals(unsecuredAPIS.size(), 2);
            Assert.assertEquals(unsecuredAPIS.get(0), "/hello-world");
            Assert.assertEquals(unsecuredAPIS.get(1), "unsecured-path");
        } finally {
            System.getProperties().remove(UNSECURED_PATHS_ENV_VARIABLE);
        }

    }

}
