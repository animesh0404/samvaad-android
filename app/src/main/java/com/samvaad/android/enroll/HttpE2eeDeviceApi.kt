package com.samvaad.android.enroll

import com.samvaad.android.AuthSession
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * HTTP enrollment boundary: `HttpURLConnection` + `org.json`, HTTPS-only,
 * no networking library. Mirrors `HttpAuthApi` conventions (timeouts,
 * `disconnect()` in `finally`, transport failures as [IOException]).
 *
 * Authentication: `Authorization: Bearer <accessToken>`. Server error bodies
 * are parsed only for the stable `reason` token on 403; nothing raw ever
 * leaves this class.
 */
class HttpE2eeDeviceApi(
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 15_000,
    /**
     * HTTPS enforcement. Always true in production; tests disable it to
     * run against a plaintext loopback stub (no TLS stack involved).
     */
    private val requireHttps: Boolean = true,
) : E2eeDeviceApi {

    override suspend fun enroll(
        session: AuthSession,
        serverAddress: String,
        request: EnrollRequest,
    ): EnrollResult = withContext(Dispatchers.IO) {
        val body = JSONObject()
            .put("registrationId", request.registrationId)
            .put("deviceIdentityPublicKey", request.deviceIdentityPublicKey)
            .put("signedPrekeyId", request.signedPrekeyId)
            .put("signedPrekey", request.signedPrekey)
            .put("signedPrekeySignature", request.signedPrekeySignature)
            .put("kyberPrekeyId", request.kyberPrekeyId)
            .put("kyberPrekey", request.kyberPrekey)
            .put("kyberPrekeySignature", request.kyberPrekeySignature)
            .put("clientPlatform", request.clientPlatform)
        request.clientName?.let { body.put("clientName", it) }
        request.clientVersion?.let { body.put("clientVersion", it) }
        val (code, response) = post(
            session, serverAddress, "/api/e2ee/devices", body.toString()
        )
        if (code != HttpURLConnection.HTTP_CREATED) {
            throw classify(code, response)
        }
        try {
            val json = JSONObject(response)
            val device = parseDevice(json.getJSONObject("device"))
            val codes = json.optJSONArray("recoveryCodes")?.let { array ->
                List(array.length(), array::getString)
            }
            EnrollResult(
                device = device,
                enrollmentState = json.getString("enrollmentState"),
                recoveryCodes = codes,
            )
        } catch (e: JSONException) {
            throw EnrollException.Transport(e)
        }
    }

    override suspend fun uploadOneTimePrekeys(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        batch: List<OneTimePrekeyUpload>,
    ): Unit = withContext(Dispatchers.IO) {
        val prekeys = JSONArray()
        batch.forEach {
            prekeys.put(
                JSONObject()
                    .put("prekeyId", it.prekeyId)
                    .put("publicKey", it.publicKey)
            )
        }
        val (code, response) = put(
            session,
            serverAddress,
            "/api/e2ee/devices/$deviceId/one-time-prekeys",
            JSONObject().put("prekeys", prekeys).toString(),
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classify(code, response)
        }
    }

    override suspend fun listDevices(
        session: AuthSession,
        serverAddress: String,
    ): DeviceList = withContext(Dispatchers.IO) {
        val (code, response) = get(session, serverAddress, "/api/e2ee/devices")
        if (code != HttpURLConnection.HTTP_OK) {
            throw classify(code, response)
        }
        try {
            val json = JSONObject(response)
            val devices = json.getJSONArray("devices")
            DeviceList(
                enrollmentState = json.getString("enrollmentState"),
                devices = List(devices.length()) { i ->
                    parseDevice(devices.getJSONObject(i))
                },
            )
        } catch (e: JSONException) {
            throw EnrollException.Transport(e)
        }
    }

    override suspend fun listRecipientDevices(
        session: AuthSession,
        serverAddress: String,
        username: String,
    ): List<RecipientDeviceRecord> = withContext(Dispatchers.IO) {
        require(username.isNotBlank()) { "username must be present" }
        val encoded = java.net.URLEncoder.encode(username.trim(), StandardCharsets.UTF_8.name())
        val (code, response) = get(session, serverAddress, "/api/e2ee/users/$encoded/devices")
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyDirectory(code, response)
        }
        try {
            val array = JSONArray(response)
            List(array.length()) { i -> parseRecipient(array.getJSONObject(i)) }
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun claimOneTimePrekey(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        requestId: java.util.UUID,
    ): ClaimedDeviceBundle = withContext(Dispatchers.IO) {
        require(deviceId.isNotBlank()) { "deviceId must be present" }
        val (code, response) = post(
            session,
            serverAddress,
            "/api/e2ee/devices/$deviceId/one-time-prekeys/claim",
            JSONObject().put("requestId", requestId.toString()).toString(),
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyDirectory(code, response)
        }
        try {
            parseClaim(JSONObject(response))
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun submitMessage(
        session: AuthSession,
        serverAddress: String,
        requestId: java.util.UUID,
        envelopes: List<MessageEnvelopeSubmit>,
    ): SubmitMessageResult = withContext(Dispatchers.IO) {
        require(envelopes.isNotEmpty()) { "at least one envelope is required" }
        val body = JSONObject()
            .put("messageRequestId", requestId.toString())
            .put("envelopes", JSONArray().also { array ->
                envelopes.forEach {
                    array.put(
                        JSONObject()
                            .put("senderDeviceId", it.senderDeviceId)
                            .put("recipientDeviceId", it.recipientDeviceId)
                            .put("envelopeType", it.envelopeType)
                            .put("ciphertext", it.ciphertextBase64)
                    )
                }
            })
            .toString()
        val (code, response) = post(session, serverAddress, "/api/e2ee/messages", body)
        // 201 = new message, 200 = identical requestId replay.
        if (code != HttpURLConnection.HTTP_OK && code != HttpURLConnection.HTTP_CREATED) {
            throw classifySubmit(code, response)
        }
        try {
            parseSubmit(JSONObject(response), createdNew = code == HttpURLConnection.HTTP_CREATED)
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    private fun parseSubmit(json: JSONObject, createdNew: Boolean): SubmitMessageResult {
        val accepted = json.getJSONArray("acceptedRecipientDevices")
        return SubmitMessageResult(
            messageId = json.getString("messageId"),
            conversationId = json.getString("conversationId"),
            sequenceNumber = json.getLong("sequenceNumber"),
            serverTimestamp = json.getString("serverTimestamp"),
            acceptedRecipientDevices = List(accepted.length(), accepted::getString),
            createdNew = createdNew,
        )
    }

    /**
     * Message-submit classifier. 403 here means sender spoof, inactive
     * sender session-device, own-device/self recipient, or non-friend —
     * never the enrollment recovery flow, so no reason-token mapping.
     */
    private fun classifySubmit(code: Int, response: String): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        HttpURLConnection.HTTP_BAD_REQUEST -> EnrollException.BadRequest()
        HttpURLConnection.HTTP_FORBIDDEN -> EnrollException.Forbidden()
        HttpURLConnection.HTTP_NOT_FOUND -> EnrollException.NotFound()
        HttpURLConnection.HTTP_CONFLICT -> EnrollException.Conflict()
        else -> EnrollException.ServerRejected()
    }

    private fun parseRecipient(json: JSONObject): RecipientDeviceRecord = RecipientDeviceRecord(
        deviceId = json.getString("deviceId"),
        registrationId = json.getInt("registrationId"),
        signalDeviceId = json.getInt("signalDeviceId"),
        deviceIdentityPublicKey = json.getString("deviceIdentityPublicKey"),
        signedPrekeyId = json.getInt("signedPrekeyId"),
        signedPrekey = json.getString("signedPrekey"),
        signedPrekeySignature = json.getString("signedPrekeySignature"),
        // Jackson serializes `isHasAvailableOneTimePrekey()` as
        // `hasAvailableOneTimePrekey`; accept either spelling defensively.
        hasAvailableOneTimePrekey = json.optBoolean("hasAvailableOneTimePrekey", false) ||
            json.optBoolean("availableOneTimePrekey", false),
        deviceRole = json.getString("deviceRole"),
        kyberPrekeyId = if (json.isNull("kyberPrekeyId")) {
            null
        } else {
            json.getInt("kyberPrekeyId")
        },
        kyberPrekey = if (json.isNull("kyberPrekey")) null else json.optString("kyberPrekey", null),
        kyberPrekeySignature = if (json.isNull("kyberPrekeySignature")) {
            null
        } else {
            json.optString("kyberPrekeySignature", null)
        },
    )

    private fun parseClaim(json: JSONObject): ClaimedDeviceBundle {
        val otpk = if (json.isNull("oneTimePrekey")) {
            null
        } else {
            val o = json.getJSONObject("oneTimePrekey")
            ClaimedOneTimePrekey(
                prekeyId = o.getInt("prekeyId"),
                publicKey = o.getString("publicKey"),
            )
        }
        return ClaimedDeviceBundle(
            deviceId = json.getString("deviceId"),
            registrationId = json.getInt("registrationId"),
            signalDeviceId = json.getInt("signalDeviceId"),
            deviceIdentityPublicKey = json.getString("deviceIdentityPublicKey"),
            signedPrekeyId = json.getInt("signedPrekeyId"),
            signedPrekey = json.getString("signedPrekey"),
            signedPrekeySignature = json.getString("signedPrekeySignature"),
            oneTimePrekey = otpk,
            deviceRole = json.getString("deviceRole"),
            kyberPrekeyId = if (json.isNull("kyberPrekeyId")) {
                null
            } else {
                json.getInt("kyberPrekeyId")
            },
            kyberPrekey = if (json.isNull("kyberPrekey")) null else json.optString("kyberPrekey", null),
            kyberPrekeySignature = if (json.isNull("kyberPrekeySignature")) {
                null
            } else {
                json.optString("kyberPrekeySignature", null)
            },
        )
    }

    /**
     * Device-discovery classifier: friendship (403) and existence (404)
     * are first-class here, unlike the enrollment paths where both map
     * to [EnrollException.ServerRejected]. The 403 recovery reason keeps
     * its existing meaning.
     */
    private fun classifyDirectory(code: Int, response: String): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        HttpURLConnection.HTTP_BAD_REQUEST -> EnrollException.BadRequest()
        HttpURLConnection.HTTP_FORBIDDEN ->
            if (responseReason(response) == RECOVERY_REQUIRED_REASON) {
                EnrollException.RecoveryRequired()
            } else {
                EnrollException.Forbidden()
            }
        HttpURLConnection.HTTP_NOT_FOUND -> EnrollException.NotFound()
        HttpURLConnection.HTTP_CONFLICT -> EnrollException.Conflict()
        else -> EnrollException.ServerRejected()
    }

    private fun parseDevice(json: JSONObject): DeviceRecord = DeviceRecord(
        deviceId = json.getString("deviceId"),
        registrationId = json.getInt("registrationId"),
        signalDeviceId = json.getInt("signalDeviceId"),
        deviceIdentityPublicKey = json.getString("deviceIdentityPublicKey"),
        signedPrekeyId = json.getInt("signedPrekeyId"),
        deviceRole = json.getString("deviceRole"),
        status = json.getString("status"),
        availablePrekeys = json.optLong("availablePrekeys", 0L),
    )

    /** Maps status codes to the typed taxonomy; the 403 reason token is inspected. */
    private fun classify(code: Int, response: String): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        HttpURLConnection.HTTP_BAD_REQUEST -> EnrollException.BadRequest()
        HttpURLConnection.HTTP_FORBIDDEN ->
            if (responseReason(response) == RECOVERY_REQUIRED_REASON) {
                EnrollException.RecoveryRequired()
            } else {
                EnrollException.ServerRejected()
            }
        HttpURLConnection.HTTP_CONFLICT -> EnrollException.Conflict()
        else -> EnrollException.ServerRejected()
    }

    /**
     * Best-effort reason extraction. Only the stable `reason` token is read;
     * the message body is never surfaced.
     */
    private fun responseReason(response: String): String? = try {
        JSONObject(response).optString("reason", null)
    } catch (_: JSONException) {
        null
    }

    private companion object {
        const val RECOVERY_REQUIRED_REASON = "E2EE_RECOVERY_REQUIRED"
    }

    private fun post(
        session: AuthSession,
        serverAddress: String,
        path: String,
        body: String,
    ): Pair<Int, String> = request(session, serverAddress, path, "POST", body)

    private fun put(
        session: AuthSession,
        serverAddress: String,
        path: String,
        body: String,
    ): Pair<Int, String> = request(session, serverAddress, path, "PUT", body)

    private fun get(
        session: AuthSession,
        serverAddress: String,
        path: String,
    ): Pair<Int, String> = request(session, serverAddress, path, "GET", null)

    private fun request(
        session: AuthSession,
        serverAddress: String,
        path: String,
        method: String,
        body: String?,
    ): Pair<Int, String> {
        if (requireHttps) {
            require(serverAddress.startsWith("https://")) { "HTTPS only" }
        }
        val connection =
            (URL(serverAddress + path).openConnection() as HttpURLConnection)
                .apply {
                    requestMethod = method
                    doOutput = body != null
                    connectTimeout = connectTimeoutMillis
                    readTimeout = readTimeoutMillis
                    setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    setRequestProperty("Accept", "application/json")
                    setRequestProperty("Authorization", "Bearer ${session.accessToken}")
                }
        try {
            body?.let {
                connection.outputStream.use { out ->
                    out.write(it.toByteArray(StandardCharsets.UTF_8))
                }
            }
            val code = connection.responseCode
            val stream =
                if (code in 200..299) connection.inputStream else connection.errorStream
            val responseBody = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            return code to responseBody
        } catch (e: IOException) {
            throw EnrollException.Transport(e)
        } finally {
            connection.disconnect()
        }
    }
}
