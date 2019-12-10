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
import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import io.cellery.security.cell.sts.server.core.model.config.CellStsConfiguration;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/**
 * Utilities for Cell STS.
 */
public class CellStsUtils {

    private static final String STS_CONFIG_PATH_ENV_VARIABLE = "CONF_PATH";
    private static final String UNSECURED_PATHS_ENV_VARIABLE = "UNSECURED_CONTEXTS_CONF_PATH";
    private static final String UNSECURED_PATHS_CONFIG_PATH = "/etc/config/unsecured-paths.json";
    private static final String CONFIG_FILE_PATH = "/etc/config/sts.json";

    public static String getMyCellName() throws CelleryCellSTSException {
        // For now we pick the cell name from the environment variable.
        String cellName = resolveSystemVariable(Constants.CELL_INSTANCE_NAME_ENV_VAR);
        if (StringUtils.isBlank(cellName)) {
            throw new CelleryCellSTSException("Environment variable '" + Constants.CELL_INSTANCE_NAME_ENV_VAR + "'" +
                    " is empty.");
        }
        return cellName;
    }

    public static String getCellImageName() {

        return resolveSystemVariable(Constants.CELL_IMAGE_NAME_ENV_VAR);
    }

    public static String getCellVersion() {

        return resolveSystemVariable(Constants.CELL_VERSION_ENV_VAR);
    }

    public static boolean isRequestToMicroGateway(CellStsRequest cellStsRequest) throws CelleryCellSTSException {

        String workload = cellStsRequest.getDestination().getWorkload();
        boolean inferFromDestinationAddress = (StringUtils.isNotEmpty(workload) &&
                workload.startsWith(CellStsUtils.getMyCellName() + "--gateway-service"));

        return (inferFromDestinationAddress || cellStsRequest.isGatewayIncomingRequest());
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
    public static String getIssuerName(String cellName, String namespace) {

        if (StringUtils.isEmpty(namespace)) {
            namespace = Constants.DEFAULT_NAMESPACE;
        }
        if (cellName.equals(Constants.COMPOSITE_CELL_NAME)) {
            return new StringBuilder(cellName).append(Constants.STS_SERVICE).append(".")
                    .append(namespace).toString();
        } else {
            return new StringBuilder(cellName).append(Constants.STS_SERVICE).append(".")
                    .append(namespace).toString();
        }
    }

    public static String getGatewayIssuer(String cellName) {
        String cellNamespace = CellStsUtils.resolveSystemVariable(Constants.CELL_NAMESPACE);
        if (StringUtils.isEmpty(cellNamespace)) {
            return new StringBuilder(cellName).append("--gateway").toString();
        }
        // If this is the initial request, no source cell is involved. Hence returning empty string.
        if (StringUtils.isEmpty(cellName)) {
            return "";
        }
        return new StringBuilder(cellName).append("--gateway.").
                append(cellNamespace).toString();
    }

    public static String getConfigFilePath() {

        String configPath = resolveSystemVariable(STS_CONFIG_PATH_ENV_VARIABLE);
        return StringUtils.isNotBlank(configPath) ? configPath : CONFIG_FILE_PATH;
    }

    public static String getUnsecuredPathsConfigPath() {

        String configPath = resolveSystemVariable(UNSECURED_PATHS_ENV_VARIABLE);
        return StringUtils.isNotBlank(configPath) ? configPath : UNSECURED_PATHS_CONFIG_PATH;
    }

    public static void buildCellStsConfiguration() throws CelleryCellSTSException {

        try {
            String configFilePath = CellStsUtils.getConfigFilePath();
            String content = new String(Files.readAllBytes(Paths.get(configFilePath)), StandardCharsets.UTF_8);
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
                    .setSTSOPAQueryPrefix((String) config.get(Constants.Configs.CONFIG_OPA_PREFIX))
                    .setAuthorizationEnabled(Boolean.parseBoolean(String.valueOf(config.get
                            (Constants.Configs.CONFIG_AUTHORIZATION_ENABLED))));
        } catch (ParseException | IOException e) {
            throw new CelleryCellSTSException("Error while setting up STS configurations", e);
        }
    }

    public static void readUnsecuredContexts() throws CelleryCellSTSException {

        String configFilePath = CellStsUtils.getUnsecuredPathsConfigPath();
        String content = null;
        try {
            content = new String(Files.readAllBytes(Paths.get(configFilePath)), StandardCharsets.UTF_8);
            JSONArray config = (JSONArray) new JSONParser().parse(content);
            List unsecuredContexts = config.subList(0, config.size());
            CellStsConfiguration.getInstance().setUnsecuredAPIS(unsecuredContexts);
        } catch (IOException | ParseException e) {
            throw new CelleryCellSTSException("Error while reading unsecured contexts from config file", e);
        }
    }

    /**
     * Checks whether the STS is running in debug mode.
     *
     * @return true if STS runs in debug mode, unless returns false.
     */
    public static boolean isRunningInDebugMode() {

        return StringUtils.isNotEmpty(resolveSystemVariable("debug"));
    }

    public static String resolveSystemVariable(String variableName) {

        String systemVariable = System.getProperty(variableName);
        if (StringUtils.isEmpty(systemVariable)) {
            systemVariable = System.getenv(variableName);
        }
        return systemVariable;
    }

    public static boolean isCompositeSTS() {

        try {
            return Constants.COMPOSITE_CELL_NAME.equalsIgnoreCase(getMyCellName());
        } catch (CelleryCellSTSException e) {
            // This exception is harmless.
            return false;
        }
    }

    public static String extractJwtFromAuthzHeader(String authzHeader) {

        if (StringUtils.isBlank(authzHeader)) {
            return null;
        }

        String[] split = authzHeader.split("\\s+");
        return split.length > 1 ? split[1] : null;
    }

    public static String getAuthorizationHeaderValue(Map<String, String> requestHeaders) {

        String celleryAuthorizationHeader = requestHeaders.get(Constants.CELLERY_AUTHORIZATION_HEADER_NAME);
        if (StringUtils.isBlank(celleryAuthorizationHeader)) {
            celleryAuthorizationHeader = requestHeaders.get(Constants.AUTHORIZATION_HEADER_NAME);
        }
        return celleryAuthorizationHeader;
    }

    public static String getNamespaceFromAddress(String address) {

        if (StringUtils.isEmpty(address)) {
            String cellNS = resolveSystemVariable(Constants.CELL_NAMESPACE);
            if (StringUtils.isNotEmpty(cellNS)) {
                return cellNS;
            }
            return Constants.DEFAULT_NAMESPACE;
        }
        String[] splitResults = address.split("\\.");
        if (splitResults == null || splitResults.length < 2) {
            return "";
        } else {
            return splitResults[1];
        }
    }
}
