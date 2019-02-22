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

package io.cellery.security.sts.endpoint.core;

/**
 * This class holds the constants related STS.
 */
public class CellerySTSConstants {

    private CellerySTSConstants() {

    }

    /**
     * This inner class holds the constants related to Cellery STS Response.
     */
    public static class CellerySTSResponse {

        public static final String STS_TOKEN = "token";
    }

    /**
     * This inner class holds the constants related Cellery STS Request.
     */
    public static class CellerySTSRequest {

        public static final String SUBJECT = "subject";
        public static final String SCOPE = "scope";
        public static final String AUDIENCE = "audience";
        public static final String USER_CONTEXT_JWT = "user-context-jwt";
    }
}
