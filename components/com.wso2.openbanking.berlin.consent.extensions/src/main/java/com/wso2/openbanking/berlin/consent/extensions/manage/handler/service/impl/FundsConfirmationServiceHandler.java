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

package com.wso2.openbanking.berlin.consent.extensions.manage.handler.service.impl;

import com.wso2.openbanking.accelerator.consent.extensions.common.ConsentException;
import com.wso2.openbanking.accelerator.consent.extensions.manage.model.ConsentManageData;
import com.wso2.openbanking.berlin.common.utils.ErrorConstants;
import com.wso2.openbanking.berlin.consent.extensions.manage.handler.request.RequestHandler;
import com.wso2.openbanking.berlin.consent.extensions.manage.handler.request.factory.RequestHandlerFactory;
import com.wso2.openbanking.berlin.consent.extensions.manage.handler.request.impl.UpdateAuthorisationResourceRequestHandler;
import com.wso2.openbanking.berlin.consent.extensions.manage.handler.service.ServiceHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Handle the Funds Confirmations service requests.
 */
public class FundsConfirmationServiceHandler implements ServiceHandler {

    private static final Log log = LogFactory.getLog(FundsConfirmationServiceHandler.class);
    private RequestHandler requestHandler;

    @Override
    public void handlePost(ConsentManageData consentManageData) throws ConsentException {

    }

    @Override
    public void handleGet(ConsentManageData consentManageData) throws ConsentException {

    }

    @Override
    public void handleDelete(ConsentManageData consentManageData) throws ConsentException {

    }

    @Override
    public void handlePut(ConsentManageData consentManageData) throws ConsentException {

    }
}
