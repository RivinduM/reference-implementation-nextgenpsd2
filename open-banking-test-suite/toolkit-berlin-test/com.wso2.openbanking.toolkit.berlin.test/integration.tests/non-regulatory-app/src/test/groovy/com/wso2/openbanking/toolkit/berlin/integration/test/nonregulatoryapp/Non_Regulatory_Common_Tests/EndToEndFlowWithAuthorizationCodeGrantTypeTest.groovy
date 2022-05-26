/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein is strictly forbidden, unless permitted by WSO2 in accordance with
 * the WSO2 Software License available at https://wso2.com/licenses/eula/3.1.
 * For specific language governing the permissions and limitations under this
 * license, please see the license as well as any agreement you’ve entered into
 * with WSO2 governing the purchase of this software and any associated services.
 */

package com.wso2.openbanking.toolkit.berlin.integration.test.nonregulatoryapp.Non_Regulatory_Common_Tests

import com.wso2.openbanking.toolkit.berlin.integration.test.nonregulatoryapp.util.AbstractNonRegulatoryFlow
import com.wso2.openbanking.toolkit.berlin.integration.test.nonregulatoryapp.util.NonRegulatoryConstants
import org.testng.Assert
import org.testng.annotations.Test

/**
 * Non-Regulatory Flow with Authorization Code Grant Type.
 */
class EndToEndFlowWithAuthorizationCodeGrantTypeTest extends AbstractNonRegulatoryFlow {

    @Test
    void "Non-Regulatory with Authorization Code Grant Type: Auth flow"() {
        doAuthorization()
        Assert.assertNotNull(code)
    }

    @Test(dependsOnMethods = "Non-Regulatory with Authorization Code Grant Type: Auth flow")
    void "Non-Regulatory with Authorization Code Grant Type: Token Generation"() {
        getUserTokenFromAuthorizationCode()
        Assert.assertNotNull(userAccessToken)

    }

    @Test(dependsOnMethods = "Non-Regulatory with Authorization Code Grant Type: Token Generation")
    void "TC1801011_Non-Regulatory with Authorization Code Grant Type: API Invocation"() {
        doApiInvocation()
        Assert.assertEquals(apiResponse.statusCode(), NonRegulatoryConstants.STATUS_CODE_201)

    }

}
