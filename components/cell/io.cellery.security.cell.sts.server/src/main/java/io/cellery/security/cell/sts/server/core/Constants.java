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

    public class Configs {

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
