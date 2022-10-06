package com.wso2.openbanking.berlin.demo.backend.services;

import net.minidev.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import static com.wso2.openbanking.berlin.demo.backend.utils.Constants.AccountService.CODE;
import static com.wso2.openbanking.berlin.demo.backend.utils.Constants.AccountService.MESSAGE;
import static com.wso2.openbanking.berlin.demo.backend.utils.Constants.AccountService.REQUEST_ID;
import static com.wso2.openbanking.berlin.demo.backend.utils.Constants.AccountService.VALID;
import static com.wso2.openbanking.berlin.demo.backend.utils.Utility.validatePaymentRequestHeader;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;

/**
 * Mock backend containing read payments data endpoints.
 */

@Path("/")
public class PaymentService {

    private static final Log log = LogFactory.getLog(PaymentService.class);

    private static final String MULTICURRENCY_ACCOUNT = "DE12345678901234567890";

    /**
     * Get details of a payment.
     *
     * @param paymentId ID of the bank account.
     * @param requestID ID of the request.
     * @return Payment details.
     */
    @GET
    @Path("/payments/{PaymentId}")
    @Produces("application/json")
    public Response getPayment(@PathParam("PaymentId") String paymentId,
                               @HeaderParam("X-Request-ID") String requestID) {

        log.info("GET /payments/{PaymentId} endpoint called.");
        JSONObject responseJSON = validatePaymentRequestHeader(requestID);
        if (!(VALID.equals(responseJSON.get(MESSAGE)))) {
            return Response.status(FORBIDDEN).entity(responseJSON.toJSONString()).build();
        }
        //Response body for a multi-currency account :pg 103
        String response = "{\n" +
                "    \"debtorAccount\": {\n" +
                "        \"iban\": \"DE12345678901234567890\",\n" +
                "        \"currency\": \"EUR\"\n" +
                "    },\n" +
                "    \"creditorName\": \"Merchant123\",\n" +
                "    \"transactionStatus\": \"RCVD\",\n" +
                "    \"creditorAccount\": {\n" +
                "        \"iban\": \"DE98765432109876543210\"\n" +
                "    },\n" +
                "    \"instructedAmount\": {\n" +
                "        \"amount\": \"123.50\",\n" +
                "        \"currency\": \"EUR\"\n" +
                "    },\n" +
                "    \"remittanceInformationUnstructured\": \"Ref Number Merchant\"\n" +
                "}";

        return Response.ok(response).header(REQUEST_ID, requestID)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, X-Token, Origin, Accept, Authorization, " +
                        "Content-Range, Content-Disposition, Content-Description")
                .allow("OPTIONS").build();
    }

    /**
     * Get details of a bulk-payment.
     *
     * @param paymentId ID of the bank account.
     * @param requestID ID of the request.
     * @return Bulk payment details.
     */
    @GET
    @Path("/bulk-payments/{PaymentId}")
    @Produces("application/json")
    public Response getBulkPayment(@PathParam("PaymentId") String paymentId,
                               @HeaderParam("X-Request-ID") String requestID) {

        log.info("GET /bulk-payments/{PaymentId} endpoint called.");
        JSONObject responseJSON = validatePaymentRequestHeader(requestID);
        if (!(VALID.equals(responseJSON.get(MESSAGE)))) {
            return Response.status(FORBIDDEN).entity(responseJSON.toJSONString()).build();
        }
        //Response body for a multi-currency account :pg 103
        String response = "{\n" +
                "    \"debtorAccount\": {\n" +
                "        \"iban\": \"DE40100100103307118608\"\n" +
                "    },\n" +
                "    \"requestedExecutionDate\": \"2025-08-01\",\n" +
                "    \"transactionStatus\": \"RCVD\",\n" +
                "    \"payments\": [\n" +
                "        {\n" +
                "            \"creditorName\": \"Merchant123\",\n" +
                "            \"creditorAccount\": {\n" +
                "                \"iban\": \"DE02100100109307118603\"\n" +
                "            },\n" +
                "            \"instructedAmount\": {\n" +
                "                \"amount\": \"123.50\",\n" +
                "                \"currency\": \"EUR\"\n" +
                "            },\n" +
                "            \"remittanceInformationUnstructured\": \"Ref Number Merchant 1\"\n" +
                "        },\n" +
                "        {\n" +
                "            \"creditorName\": \"Merchant456\",\n" +
                "            \"creditorAccount\": {\n" +
                "                \"iban\": \"FR7612345987650123456789014\"\n" +
                "            },\n" +
                "            \"instructedAmount\": {\n" +
                "                \"amount\": \"34.10\",\n" +
                "                \"currency\": \"EUR\"\n" +
                "            },\n" +
                "            \"remittanceInformationUnstructured\": \"Ref Number Merchant 2\"\n" +
                "        }\n" +
                "    ],\n" +
                "    \"batchBookingPreferred\": true\n" +
                "}";

        return Response.ok(response).header(REQUEST_ID, requestID)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, X-Token, Origin, Accept, Authorization, " +
                        "Content-Range, Content-Disposition, Content-Description")
                .allow("OPTIONS").build();
    }

    /**
     * Get details of a periodic-payment.
     *
     * @param paymentId ID of the bank account.
     * @param requestID ID of the request.
     * @return Pariodic payment details.
     */
    @GET
    @Path("/periodic-payments/{PaymentId}")
    @Produces("application/json")
    public Response getPeriodicPayment(@PathParam("PaymentId") String paymentId,
                               @HeaderParam("X-Request-ID") String requestID) {

        log.info("GET /periodic-payments/{PaymentId} endpoint called.");
        JSONObject responseJSON = validatePaymentRequestHeader(requestID);
        if (!(VALID.equals(responseJSON.get(MESSAGE)))) {
            return Response.status(FORBIDDEN).entity(responseJSON.toJSONString()).build();
        }
        //Response body for a multi-currency account :pg 103
        String response = "{\n" +
                "    \"executionRule\": \"following\",\n" +
                "    \"debtorAccount\": {\n" +
                "        \"iban\": \"DE12345678901234567890\"\n" +
                "    },\n" +
                "    \"creditorName\": \"Merchant123\",\n" +
                "    \"transactionStatus\": \"RCVD\",\n" +
                "    \"endDate\": \"2023-09-10\",\n" +
                "    \"dayOfExecution\": \"01\",\n" +
                "    \"creditorAccount\": {\n" +
                "        \"iban\": \"DE98765432109876543210\"\n" +
                "    },\n" +
                "    \"instructedAmount\": {\n" +
                "        \"amount\": \"123.50\",\n" +
                "        \"currency\": \"EUR\"\n" +
                "    },\n" +
                "    \"remittanceInformationUnstructured\": \"Ref Number Abonnement\",\n" +
                "    \"startDate\": \"2023-09-05\",\n" +
                "    \"frequency\": \"Monthly\"\n" +
                "}";

        return Response.ok(response).header(REQUEST_ID, requestID)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, X-Token, Origin, Accept, Authorization, " +
                        "Content-Range, Content-Disposition, Content-Description")
                .allow("OPTIONS").build();
    }

    /**
     * Get details of a periodic-payment.
     *
     * @param paymentId ID of the bank account.
     * @param requestID ID of the request.
     * @return Periodic payment details.
     */
    @GET
    @Path("/{payment-service}/{PaymentId}/status")
    @Produces("application/json")
    public Response getPaymentStatus(@PathParam("payment-service") String paymentService,
                                     @PathParam("PaymentId") String paymentId,
                                     @HeaderParam("X-Request-ID") String requestID) {

        log.info("GET /periodic-payments/{PaymentId} endpoint called.");
        JSONObject responseJSON = validatePaymentRequestHeader(requestID);
        if (!(VALID.equals(responseJSON.get(MESSAGE)))) {
            return Response.status(FORBIDDEN).entity(responseJSON.toJSONString()).build();
        }
        //Response body for a multi-currency account :pg 103
        String response = "{\n" +
                "  \"transactionStatus\": \"ACCP\"\n" +
                "}";

        if (StringUtils.equals(paymentService, "bulk-payments") || StringUtils.equals(paymentService, "payments")
                || StringUtils.equals(paymentService, "periodic-payments")) {
            return Response.ok(response).header(REQUEST_ID, requestID)
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Credentials", "true")
                    .header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
                    .header("Access-Control-Allow-Headers", "Content-Type, X-Token, Origin, Accept, Authorization, " +
                            "Content-Range, Content-Disposition, Content-Description")
                    .allow("OPTIONS").build();
        } else {
            JSONObject responseJson = new JSONObject();
            responseJSON.put(CODE, FORBIDDEN.getStatusCode());
            responseJSON.put(MESSAGE, "X-Request_ID not found");
            return Response.status(FORBIDDEN).entity(responseJson.toJSONString()).build();
        }
    }
}
