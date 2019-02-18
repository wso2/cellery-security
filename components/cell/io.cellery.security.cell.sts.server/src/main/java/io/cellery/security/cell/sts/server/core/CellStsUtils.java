/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.cellery.security.cell.sts.server.core.model.config.CellStsConfiguration;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

public class CellStsUtils {

    private static final String CELL_NAME_ENV_VARIABLE = "CELL_NAME";
    private static final String STS_CONFIG_PATH_ENV_VARIABLE = "CONF_PATH";
    private static final String CONFIG_FILE_PATH = "/etc/config/sts.json";

    public static String getMyCellName() throws CelleryCellSTSException {
        // For now we pick the cell name from the environment variable.
        String cellName = System.getenv(CELL_NAME_ENV_VARIABLE);
        if (StringUtils.isBlank(cellName)) {
            throw new CelleryCellSTSException("Environment variable '" + CELL_NAME_ENV_VARIABLE + "' is empty.");
        }
        return cellName;
    }

    public static boolean isWorkloadExternalToCellery(String destinationWorkloadName) {
        // For now the only way to check whether the destination is outside of Cell mesh is by checking whether the
        // destination workload name does not comply to the format <cell-name>--<service_name>
        // Eg: hr--employee-service
        // Once we find a smarter way to check whether the target is outside of Cellery we can replace this not-so-smart
        // logic.
        return !StringUtils.contains(destinationWorkloadName, "--");
    }

    public static String getPrettyPrintJson(Map<String, String> attributes) {

        JSONObject configJson = new JSONObject();
        attributes.forEach((key, value) -> configJson.put(key, value));

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(configJson);
    }

    /**
     * Returns the issuer name.
     *
     * @param cellName Name of the cell.
     * @return Issuer name of the respective cell.
     */
    public static String getIssuerName(String cellName) {

        return cellName + "--sts-service";
    }

    public static String getConfigFilePath() {

        String configPath = System.getenv(STS_CONFIG_PATH_ENV_VARIABLE);
        return StringUtils.isNotBlank(configPath) ? configPath : CONFIG_FILE_PATH;
    }

    public static void buildCellStsConfiguration() throws CelleryCellSTSException {

        try {
            String configFilePath = CellStsUtils.getConfigFilePath();
            String content = new String(Files.readAllBytes(Paths.get(configFilePath)));
            JSONObject config = (JSONObject) new JSONParser().parse(content);

            CellStsConfiguration.getInstance()
                    .setCellName(getMyCellName())
                    .setStsEndpoint((String) config.get(Constants.Configs.CONFIG_STS_ENDPOINT))
                    .setUsername((String) config.get(Constants.Configs.CONFIG_AUTH_USERNAME))
                    .setPassword((String) config.get(Constants.Configs.CONFIG_AUTH_PASSWORD))
                    .setGlobalJWKEndpoint((String) config.get(Constants.Configs.CONFIG_GLOBAL_JWKS))
                    .setSignatureValidationEnabled(Boolean.parseBoolean(String.valueOf(config.get
                            (Constants.Configs.CONFIG_SIGNATURE_VALIDATION_ENABLED))))
                    .setAudienceValidationEnabled(Boolean.parseBoolean(String.valueOf(config.get
                            (Constants.Configs.CONFIG_AUDIENCE_VALIDATION_ENABLED))))
                    .setIssuerValidationEnabled(Boolean.parseBoolean(String.valueOf(config.get
                            (Constants.Configs.CONFIG_ISSUER_VALIDATION_ENABLED))))
                    .setSTSOPAQueryPrefix((String)config.get(Constants.Configs.CONFIG_OPA_PREFIX))
                    .setAuthorizationEnabled(Boolean.parseBoolean(String.valueOf(config.get
                            (Constants.Configs.CONFIG_AUTHORIZATION_ENABLED))));
        } catch (ParseException | IOException e) {
            throw new CelleryCellSTSException("Error while setting up STS configurations", e);
        }
    }

}
