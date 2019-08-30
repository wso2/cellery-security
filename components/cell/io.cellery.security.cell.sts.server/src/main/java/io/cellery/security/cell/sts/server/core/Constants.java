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

/**
 * Constants for STS
 */
public class Constants {

    public static final String CELLERY_AUTH_SUBJECT_HEADER = "x-cellery-auth-subject";
    public static final String AUTHORIZATION_HEADER_NAME = "authorization";
    public static final String CELLERY_AUTHORIZATION_HEADER_NAME = "cellery-authorization";
    public static final String CELL_IMAGE_NAME = "cellImageName";
    public static final String CELL_INSTANCE_NAME = "cellInstanceName";
    public static final String CELL_VERSION = "cellVersion";
    public static final String DESTINATION = "destination";
    public static final String CELL_IMAGE_NAME_ENV_VAR = "CELL_IMAGE_NAME";
    public static final String CELL_INSTANCE_NAME_ENV_VAR = "CELL_INSTANCE_NAME";
    public static final String CELL_ORG_NAME_ENV_VAR = "CELL_ORG_NAME";
    public static final String CELL_VERSION_ENV_VAR = "CELL_IMAGE_VERSION";
    public static final String COMPOSITE_CELL_NAME = "composite";

    /**
     * Configuration constants.
     */
    public static class Configs {

        public static final String CONFIG_STS_ENDPOINT = "endpoint";
        public static final String CONFIG_AUTH_USERNAME = "username";
        public static final String CONFIG_AUTH_PASSWORD = "password";
        public static final String CONFIG_GLOBAL_JWKS = "globalJWKS";
        public static final String CONFIG_SIGNATURE_VALIDATION_ENABLED = "enableSignatureValidation";
        public static final String CONFIG_ISSUER_VALIDATION_ENABLED = "enableIssuerValidation";
        public static final String CONFIG_AUDIENCE_VALIDATION_ENABLED = "enableAudienceValidation";
        public static final String CONFIG_AUTHORIZATION_ENABLED = "enableAuthorization";
        public static final String CONFIG_OPA_PREFIX = "OPAQueryPrefix";
    }

}
