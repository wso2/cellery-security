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

import io.cellery.security.cell.sts.server.core.CelleryCellSTSServer;
import io.cellery.security.cell.sts.server.core.Constants;
import io.cellery.security.cell.sts.server.core.exception.CellSTSRequestValidationFailedException;
import io.cellery.security.cell.sts.server.core.model.CellStsRequest;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

/**
 * Default implementation of cell STS request validator.
 */
public class DefaultCellSTSReqValidator implements CellSTSRequestValidator {

    private static final Logger log = LoggerFactory.getLogger(CelleryCellSTSServer.class);
    private List<String> unAuthenticatedAPIs;

    public DefaultCellSTSReqValidator(List<String> unAuthenticatedAPIs) {

        this.unAuthenticatedAPIs = unAuthenticatedAPIs;
    }

    @Override
    public void validate(CellStsRequest cellStsRequest) throws CellSTSRequestValidationFailedException {

        String subject = cellStsRequest.getRequestHeaders().get(Constants.CELLERY_AUTH_SUBJECT_HEADER);
        if (StringUtils.isNotBlank(subject)) {
            throw new CellSTSRequestValidationFailedException("A subject header is found in the inbound request," +
                    " before security validation: " + subject);
        }
    }

    @Override
    public boolean isAuthenticationRequired(CellStsRequest cellStsRequest) throws
            CellSTSRequestValidationFailedException {

        String path = cellStsRequest.getRequestContext().getPath();
        Optional<String> unProtectedResult = unAuthenticatedAPIs.stream().
                filter(unProtectedPath -> StringUtils.equals(path, unProtectedPath)).findAny();
        if (unProtectedResult.isPresent()) {
            return false;
        }
        return true;
    }

}
