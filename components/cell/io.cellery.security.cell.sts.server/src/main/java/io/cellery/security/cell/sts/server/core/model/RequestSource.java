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
package io.cellery.security.cell.sts.server.core.model;

import io.cellery.security.cell.sts.server.core.CellStsUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Object model to represent source of the GPRC request.
 */
public class RequestSource {

    private String cellInstanceName;
    private String workload;

    private RequestSource() {

    }

    public String getCellInstanceName() {

        return cellInstanceName;
    }

    public String getWorkload() {

        return workload;
    }

    @Override
    public String toString() {

        Map<String, String> configJson = new HashMap<>();
        configJson.put("Cell Instance Name", cellInstanceName);
        configJson.put("Workload", workload);

        return CellStsUtils.getPrettyPrintJson(configJson);
    }

    /**
     * Request Builder.
     */
    public static class RequestSourceBuilder {

        private String cellInstanceName;
        private String workload;

        public RequestSourceBuilder setWorkload(String workload) {

            this.workload = workload;
            return this;
        }

        public RequestSourceBuilder setCellInstanceName(String cellInstanceName) {

            this.cellInstanceName = cellInstanceName;
            return this;
        }

        public RequestSource build() {

            RequestSource requestSource = new RequestSource();
            requestSource.cellInstanceName = cellInstanceName;
            requestSource.workload = workload;
            return requestSource;
        }
    }
}
