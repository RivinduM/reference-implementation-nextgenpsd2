/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 *  This software is the property of WSO2 Inc. and its suppliers, if any.
 *  Dissemination of any information or reproduction of any material contained
 *  herein is strictly forbidden, unless permitted by WSO2 in accordance with
 *  the WSO2 Software License available at https://wso2.com/licenses/eula/3.1.
 *  For specific language governing the permissions and limitations under this
 *  license, please see the license as well as any agreement you’ve entered into
 *  with WSO2 governing the purchase of this software and any associated services.
 */

package com.wso2.openbanking.berlin.consent.extensions.authorize.common.impl;

import com.wso2.openbanking.accelerator.consent.mgt.dao.models.AuthorizationResource;
import com.wso2.openbanking.berlin.consent.extensions.authorize.common.AuthorisationStateChangeHook;
import com.wso2.openbanking.berlin.consent.extensions.authorize.enums.AuthorisationAggregateStatusEnum;

/**
 * Authorisation state change hook for funds confirmations service.
 */
public class FundsConfirmationsStateChangeHook implements AuthorisationStateChangeHook {

    @Override
    public String onAuthorisationStateChange(String consentId, String authType,
                                           AuthorisationAggregateStatusEnum aggregatedStatus,
                                           AuthorizationResource currentAuthorisation) {

        // todo: Implement for funds confirmation flow
        return null;
    }
}
