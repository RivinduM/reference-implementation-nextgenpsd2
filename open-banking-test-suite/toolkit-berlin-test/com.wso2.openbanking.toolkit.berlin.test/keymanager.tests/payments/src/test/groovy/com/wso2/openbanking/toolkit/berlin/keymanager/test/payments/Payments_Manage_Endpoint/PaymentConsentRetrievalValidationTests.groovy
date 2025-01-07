/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.wso2.openbanking.toolkit.berlin.keymanager.test.payments.Payments_Manage_Endpoint

import com.wso2.openbanking.berlin.common.utils.BerlinConstants
import com.wso2.openbanking.toolkit.berlin.keymanager.test.payments.util.AbstractPaymentsFlow
import com.wso2.openbanking.toolkit.berlin.keymanager.test.payments.util.PaymentsConstants
import com.wso2.openbanking.toolkit.berlin.keymanager.test.payments.util.PaymentsInitiationPayloads
import org.testng.Assert
import org.testng.annotations.Test

/**
 * Payment Consent Retrieval Validation Tests.
 */
class PaymentConsentRetrievalValidationTests extends AbstractPaymentsFlow {

	String consentPath
	String initiationPayload

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"], priority = 1)
	void "OB-1498_Retrieve Single Payment Consent Details"() {

		consentPath = PaymentsConstants.SINGLE_PAYMENTS_CONSENT_PATH
		initiationPayload = PaymentsInitiationPayloads.singlePaymentPayload

		//Payment Initiation
		doDefaultInitiation(consentPath, initiationPayload)

		Assert.assertEquals(consentResponse.statusCode(), BerlinConstants.STATUS_CODE_201)
		Assert.assertNotNull(paymentId)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)

		//Consent Retrieval
		String retrievalPath = consentPath + "/$paymentId"

		doConsentRetrieval(retrievalPath)
		Assert.assertEquals(consentRetrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"],
					dependsOnMethods = "OB-1498_Retrieve Single Payment Consent Details", priority = 2)
	void "OB-1501_Retrieve Single Payment Consent Status"() {

		doStatusRetrieval(consentPath)
		Assert.assertEquals(retrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"], priority = 3)
	void "OB-1499_Retrieve Bulk Payment Consent Details"() {

		consentPath = PaymentsConstants.BULK_PAYMENTS_CONSENT_PATH
		initiationPayload = PaymentsInitiationPayloads.bulkPaymentPayload

		//Payment Initiation
		doDefaultInitiation(consentPath, initiationPayload)

		Assert.assertEquals(consentResponse.statusCode(), BerlinConstants.STATUS_CODE_201)
		Assert.assertNotNull(paymentId)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)

		//Consent Retrieval
		String retrievalPath = consentPath + "/$paymentId"

		doConsentRetrieval(retrievalPath)
		Assert.assertEquals(consentRetrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"],
					dependsOnMethods = "OB-1499_Retrieve Bulk Payment Consent Details", priority = 4)
	void "OB-1502_Retrieve Bulk Payment Consent Status"() {

		doStatusRetrieval(consentPath)
		Assert.assertEquals(retrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"], priority = 5)
	void "OB-1500_Retrieve Periodic Payment Consent Details"() {

		consentPath = PaymentsConstants.PERIODIC_PAYMENTS_CONSENT_PATH
		initiationPayload = PaymentsInitiationPayloads.periodicPaymentPayload

		//Payment Initiation
		doDefaultInitiation(consentPath, initiationPayload)

		Assert.assertEquals(consentResponse.statusCode(), BerlinConstants.STATUS_CODE_201)
		Assert.assertNotNull(paymentId)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)

		//Consent Retrieval
		String retrievalPath = consentPath + "/$paymentId"

		doConsentRetrieval(retrievalPath)
		Assert.assertEquals(consentRetrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"],
					dependsOnMethods = "OB-1500_Retrieve Periodic Payment Consent Details", priority = 6)
	void "OB-1503_Retrieve Periodic Payment Consent Status"() {

		doStatusRetrieval(consentPath)
		Assert.assertEquals(retrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)
	}

	@Test (groups = ["1.3.3", "1.3.6"], priority = 7)
	void "OB-1504_Retrieve Consent Details for Authorised Consent"() {

		consentPath = PaymentsConstants.SINGLE_PAYMENTS_CONSENT_PATH
		initiationPayload = PaymentsInitiationPayloads.singlePaymentPayload

		//Payment Initiation
		doDefaultInitiation(consentPath, initiationPayload)

		Assert.assertEquals(consentResponse.statusCode(), BerlinConstants.STATUS_CODE_201)
		Assert.assertNotNull(paymentId)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)

		doAuthorizationFlow()
		Assert.assertNotNull(code)

		//Consent Retrieval
		String retrievalPath = consentPath + "/$paymentId"

		doConsentRetrieval(retrievalPath)
		Assert.assertEquals(consentRetrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_ACCP)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"],
					dependsOnMethods = "OB-1504_Retrieve Consent Details for Authorised Consent", priority = 8)
	void "OB-1505_Retrieve Consent status from Authorised Consent"() {

		doStatusRetrieval(consentPath)
		Assert.assertEquals(retrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_ACCP)
	}

	@Test (groups = ["1.3.3", "1.3.6"], priority = 9)
	void "OB-1506_Retrieve Consent Details from Rejected Consent"() {

		consentPath = PaymentsConstants.SINGLE_PAYMENTS_CONSENT_PATH
		initiationPayload = PaymentsInitiationPayloads.singlePaymentPayload

		//Payment Initiation
		doDefaultInitiation(consentPath, initiationPayload)

		Assert.assertEquals(consentResponse.statusCode(), BerlinConstants.STATUS_CODE_201)
		Assert.assertNotNull(paymentId)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)

		//Delete Consent
		doConsentDenyFlow()
		Assert.assertEquals(code, "User denied the consent")

		//Consent Retrieval
		def retrievalConsentPath = consentPath + "/$paymentId"
		doConsentRetrieval(retrievalConsentPath)
		Assert.assertEquals(consentRetrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_REJECTED)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"],
					dependsOnMethods = "OB-1506_Retrieve Consent Details from Rejected Consent", priority = 10)
	void "OB-1507_Retrieve Consent status from Rejected Consent"() {

		doStatusRetrieval(consentPath)
		Assert.assertEquals(retrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_REJECTED)
	}

	@Test (groups = ["1.3.3", "1.3.6"], priority = 11)
	void "OB-1508_Retrieve Consent Details from Revoked Consent"() {

		consentPath = PaymentsConstants.PERIODIC_PAYMENTS_CONSENT_PATH
		initiationPayload = PaymentsInitiationPayloads.periodicPaymentPayload

		//Payment Initiation
		doDefaultInitiation(consentPath, initiationPayload)

		Assert.assertEquals(consentResponse.statusCode(), BerlinConstants.STATUS_CODE_201)
		Assert.assertNotNull(paymentId)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_RECEIVED)

		//Delete Consent
		def retrievalConsentPath = consentPath + "/$paymentId"
		doConsentDelete(retrievalConsentPath)
		Assert.assertEquals(deleteResponse.getStatusCode(), BerlinConstants.STATUS_CODE_204)
		Assert.assertNotNull(deleteResponse.getHeader("X-Request-ID"))

		//Consent Retrieval
		doConsentRetrieval(retrievalConsentPath)
		Assert.assertEquals(consentRetrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_CANC)
	}

	@Test (groups = ["SmokeTest", "1.3.3", "1.3.6"],
					dependsOnMethods = "OB-1508_Retrieve Consent Details from Revoked Consent", priority = 12)
	void "OB-1509_Retrieve Consent Status from Revoked Consent"() {

		doStatusRetrieval(consentPath)
		Assert.assertEquals(retrievalResponse.statusCode(), BerlinConstants.STATUS_CODE_200)
		Assert.assertEquals(consentStatus, PaymentsConstants.TRANSACTION_STATUS_CANC)
	}
}
