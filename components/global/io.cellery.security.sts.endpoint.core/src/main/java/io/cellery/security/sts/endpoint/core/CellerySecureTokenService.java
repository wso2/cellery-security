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

import com.nimbusds.jwt.SignedJWT;
import io.cellery.security.extensions.exception.CelleryAuthException;
import io.cellery.security.extensions.jwt.CellerySignedJWTBuilder;
import io.cellery.security.extensions.util.Utils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class issues the JWT taken for the STS request in Cellery.
 */
public class CellerySecureTokenService {

    public CellerySTSResponse issueJWT(CellerySTSRequest tokenRequest) throws CellerySTSException {

        // TODO we need to validate stuff before issuing the security...
        try {
            String subject = tokenRequest.getSource();
            Map<String, Object> claims = new HashMap<>();

            if (StringUtils.isNotBlank(tokenRequest.getUserContextJwt())) {
                // TODO: add logs here.
                // If a user context jwt is set this is a security requested to impersonate a user.
                SignedJWT userContextJwt = SignedJWT.parse(tokenRequest.getUserContextJwt());
                if (isUserContextJwtValid(userContextJwt)) {
                    subject = userContextJwt.getJWTClaimsSet().getSubject();
                    claims.putAll(Utils.getCustomClaims(userContextJwt));
                } else {
                    throw new CellerySTSException("Invalid user context JWT presented to obtain a STS security.");
                }
            }

            String jwt = new CellerySignedJWTBuilder()
                    .subject(subject)
                    .scopes(tokenRequest.getScopes())
                    .audience(tokenRequest.getAudiences())
                    .claims(claims)
                    .build();

            CellerySTSResponse cellerySTSResponse = new CellerySTSResponse();
            cellerySTSResponse.setStsToken(jwt);

            return cellerySTSResponse;
        } catch (CelleryAuthException e) {
            throw new CellerySTSException("Error issuing JWT.", e);
        } catch (ParseException e) {
            throw new CellerySTSException("Error while parsing the user context JWT", e);
        }
    }

    private boolean isUserContextJwtValid(SignedJWT userContextJwt) throws CelleryAuthException {
        // We can't blindly trust the user context JWT present. So we do a signature verification to see if it was
        // issued by the Cellery core
        try {
            IdentityProvider idp = Utils.getCelleryIDP();
            return Utils.validateSignature(userContextJwt, idp);
        } catch (IdentityProviderManagementException | IdentityOAuth2Exception e) {
            throw new CelleryAuthException("Error while validating user context jwt", e);
        }
    }

}
