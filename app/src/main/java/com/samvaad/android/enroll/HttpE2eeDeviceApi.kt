package com.samvaad.android.enroll

import com.samvaad.android.AuthSession
import com.samvaad.android.crypto.SpikeCryptoMaterial
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
        val body = enrollJson(request)
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

    private fun enrollJson(request: EnrollRequest): JSONObject = JSONObject()
        .put("registrationId", request.registrationId)
        .put("deviceIdentityPublicKey", request.deviceIdentityPublicKey)
        .put("signedPrekeyId", request.signedPrekeyId)
        .put("signedPrekey", request.signedPrekey)
        .put("signedPrekeySignature", request.signedPrekeySignature)
        .put("kyberPrekeyId", request.kyberPrekeyId)
        .put("kyberPrekey", request.kyberPrekey)
        .put("kyberPrekeySignature", request.kyberPrekeySignature)
        .put("clientPlatform", request.clientPlatform)

    override suspend fun approveDevice(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
    ): DeviceRecord = withContext(Dispatchers.IO) {
        require(deviceId.isNotBlank()) { "deviceId must be present" }
        // The contract takes no request body; `{}` keeps the shared POST
        // helper (which always frames a JSON body) without inventing fields.
        val (code, response) = post(
            session, serverAddress, "/api/e2ee/devices/$deviceId/approve", "{}"
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyDeviceAction(code, response)
        }
        try {
            parseDevice(JSONObject(response))
        } catch (e: JSONException) {
            throw EnrollException.Transport(e)
        }
    }

    override suspend fun bindDevice(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        recoveryCode: String,
    ): DeviceRecord = withContext(Dispatchers.IO) {
        require(deviceId.isNotBlank()) { "deviceId must be present" }
        // Blank codes fail locally: they can never be valid, and must not
        // reach the wire (a used/blank code is indistinguishable from a
        // wrong one once sent).
        require(recoveryCode.isNotBlank()) { "recovery code must be present" }
        val (code, response) = post(
            session,
            serverAddress,
            "/api/e2ee/devices/$deviceId/bind",
            JSONObject().put("recoveryCode", recoveryCode).toString(),
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyDeviceAction(code, response)
        }
        try {
            parseDevice(JSONObject(response))
        } catch (e: JSONException) {
            throw EnrollException.Transport(e)
        }
    }

    override suspend fun beginAttach(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
    ): AttachBegin = withContext(Dispatchers.IO) {
        require(deviceId.isNotBlank()) { "deviceId must be present" }
        // The contract takes no request body; `{}` keeps the shared POST
        // helper (which always frames a JSON body) without inventing fields.
        val (code, response) = post(
            session, serverAddress, "/api/e2ee/devices/$deviceId/attach/begin", "{}"
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyDeviceAction(code, response)
        }
        try {
            val json = JSONObject(response)
            if (json.optBoolean("bound", false)) {
                AttachBegin.AlreadyBound(parseDevice(json.getJSONObject("device")))
            } else {
                AttachBegin.Challenge(
                    challengeId = json.getString("challengeId"),
                    serverEphemeralPublicKey = json.getString("serverEphemeralPublicKey"),
                    expiresAt = json.optString("expiresAt", null),
                )
            }
        } catch (e: JSONException) {
            throw EnrollException.Transport(e)
        }
    }

    override suspend fun completeAttach(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        challengeId: String,
        proofBase64: String,
    ): DeviceRecord = withContext(Dispatchers.IO) {
        require(deviceId.isNotBlank()) { "deviceId must be present" }
        require(challengeId.isNotBlank()) { "challengeId must be present" }
        require(proofBase64.isNotBlank()) { "proof must be present" }
        val (code, response) = post(
            session,
            serverAddress,
            "/api/e2ee/devices/$deviceId/attach/complete",
            JSONObject()
                .put("challengeId", challengeId)
                .put("proof", proofBase64)
                .toString(),
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyDeviceAction(code, response)
        }
        try {
            parseDevice(JSONObject(response))
        } catch (e: JSONException) {
            throw EnrollException.Transport(e)
        }
    }

    override suspend fun recoverEnroll(
        session: AuthSession,
        serverAddress: String,
        recoveryCode: String,
        request: EnrollRequest,
    ): DeviceRecord = withContext(Dispatchers.IO) {
        require(recoveryCode.isNotBlank()) { "recovery code must be present" }
        val body = JSONObject()
            .put("recoveryCode", recoveryCode)
            .put("device", enrollJson(request))
        request.clientName?.let { body.getJSONObject("device").put("clientName", it) }
        request.clientVersion?.let { body.getJSONObject("device").put("clientVersion", it) }
        val (code, response) = post(
            session, serverAddress, "/api/e2ee/recovery/enroll", body.toString()
        )
        if (code != HttpURLConnection.HTTP_CREATED) {
            throw classifyDeviceAction(code, response)
        }
        try {
            parseDevice(JSONObject(response))
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

    override suspend fun fetchMailbox(
        session: AuthSession,
        serverAddress: String,
        limit: Int,
    ): List<MailboxItem> = withContext(Dispatchers.IO) {
        require(limit in 1..100) { "mailbox limit must be 1..100" }
        val (code, response) = get(session, serverAddress, "/api/e2ee/mailbox?limit=$limit")
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyMailbox(code)
        }
        try {
            val array = JSONArray(response)
            List(array.length()) { i -> parseMailboxItem(array.getJSONObject(i)) }
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun ackMailbox(
        session: AuthSession,
        serverAddress: String,
        messageIds: List<java.util.UUID>,
    ): Int = withContext(Dispatchers.IO) {
        val ids = JSONArray()
        messageIds.forEach { ids.put(it.toString()) }
        val (code, response) = post(
            session,
            serverAddress,
            "/api/e2ee/mailbox/ack",
            JSONObject().put("messageIds", ids).toString(),
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyAck(code)
        }
        try {
            JSONObject(response).getInt("acknowledged")
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    private fun parseMailboxItem(json: JSONObject): MailboxItem =
        com.samvaad.android.enroll.parseMailboxItem(json)

    /**
     * Mailbox-fetch classifier. The server answers 200 (including `[]`
     * for unbound sessions) or 401; no other fetch status exists, so
     * anything else is an unexpected rejection.
     */
    private fun classifyMailbox(code: Int): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        else -> EnrollException.ServerRejected()
    }

    /** ACK classifier: bound-ACTIVE-device required, else 403. */
    private fun classifyAck(code: Int): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        HttpURLConnection.HTTP_FORBIDDEN -> EnrollException.Forbidden()
        else -> EnrollException.ServerRejected()
    }

    override suspend fun fetchHistory(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        afterSequence: Long,
        limit: Int,
    ): List<HistoryItem> = withContext(Dispatchers.IO) {
        require(conversationId.isNotBlank()) { "conversationId must be present" }
        require(afterSequence >= 0) { "afterSequence must be >= 0" }
        require(limit in 1..100) { "history limit must be 1..100" }
        // UUIDs carry only hex + hyphens, but validate shape anyway so a
        // malformed identifier fails locally instead of hitting the wire.
        java.util.UUID.fromString(conversationId)
        val (code, response) = get(
            session,
            serverAddress,
            "/api/e2ee/conversations/$conversationId/messages?afterSequence=$afterSequence&limit=$limit",
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyHistory(code)
        }
        try {
            val array = JSONArray(response)
            List(array.length()) { i -> parseHistoryItem(array.getJSONObject(i)) }
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        } catch (e: IllegalArgumentException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun getSyncCursor(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
    ): SyncCursor = withContext(Dispatchers.IO) {
        require(conversationId.isNotBlank()) { "conversationId must be present" }
        java.util.UUID.fromString(conversationId)
        val (code, response) = get(
            session, serverAddress, "/api/e2ee/sync?conversationId=$conversationId"
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyHistory(code)
        }
        try {
            parseCursor(JSONObject(response))
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun advanceSyncCursor(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        throughSequence: Long,
    ): SyncCursor = withContext(Dispatchers.IO) {
        require(conversationId.isNotBlank()) { "conversationId must be present" }
        require(throughSequence >= 0) { "throughSequence must be >= 0" }
        java.util.UUID.fromString(conversationId)
        val (code, response) = put(
            session,
            serverAddress,
            "/api/e2ee/sync",
            JSONObject()
                .put("conversationId", conversationId)
                .put("throughSequence", throughSequence)
                .toString(),
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifyHistory(code)
        }
        try {
            parseCursor(JSONObject(response))
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun listConversations(
        session: AuthSession,
        serverAddress: String,
        limit: Int,
    ): List<String> = withContext(Dispatchers.IO) {
        require(limit in 1..100) { "conversation list limit must be 1..100" }
        val (code, response) = get(
            session, serverAddress, "/api/conversations/direct?limit=$limit&offset=0"
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifySync(code)
        }
        try {
            val array = JSONArray(response)
            List(array.length()) { i -> array.getJSONObject(i).getString("conversationId") }
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun uploadSyncBatch(
        session: AuthSession,
        serverAddress: String,
        request: SyncUploadRequest,
    ): SyncUploadResult = withContext(Dispatchers.IO) {
        require(request.items.isNotEmpty()) { "sync batch must contain at least one item" }
        val items = JSONArray()
        request.items.forEach {
            items.put(
                JSONObject()
                    .put("messageId", it.messageId)
                    .put("sequenceNumber", it.sequenceNumber)
                    .put("senderDeviceId", it.senderDeviceId)
                    .put("envelopeType", it.envelopeType)
                    .put("ciphertext", it.ciphertextBase64)
            )
        }
        val body = JSONObject()
            .put("syncBatchId", request.syncBatchId.toString())
            .put("recipientDeviceId", request.recipientDeviceId)
            .put("conversationId", request.conversationId)
            .put("fromSequence", request.fromSequence)
            .put("frontier", request.frontier)
            .put("items", items)
            .toString()
        val (code, response) =
            post(session, serverAddress, "/api/e2ee/sync-history/batches", body)
        when (code) {
            HttpURLConnection.HTTP_CREATED -> parseSyncUpload(response, createdNew = true)
            HttpURLConnection.HTTP_OK -> parseSyncUpload(response, createdNew = false)
            else -> throw classifySync(code)
        }
    }

    override suspend fun fetchSyncBatch(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        afterSequence: Long,
        limit: Int,
    ): List<SyncBatchItem> = withContext(Dispatchers.IO) {
        require(conversationId.isNotBlank()) { "conversationId must be present" }
        require(afterSequence >= 0) { "afterSequence must be >= 0" }
        require(limit in 1..100) { "sync fetch limit must be 1..100" }
        java.util.UUID.fromString(conversationId)
        val (code, response) = get(
            session,
            serverAddress,
            "/api/e2ee/sync-history/batches?conversationId=$conversationId" +
                "&afterSequence=$afterSequence&limit=$limit",
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifySync(code)
        }
        try {
            val array = JSONArray(response)
            List(array.length()) { i -> parseSyncBatchItem(array.getJSONObject(i), conversationId) }
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        } catch (e: IllegalArgumentException) {
            throw EnrollException.Malformed(e)
        }
    }

    override suspend fun ackSync(
        session: AuthSession,
        serverAddress: String,
        conversationId: String,
        throughSequence: Long,
    ): SyncAckResult = withContext(Dispatchers.IO) {
        require(conversationId.isNotBlank()) { "conversationId must be present" }
        require(throughSequence >= 0) { "throughSequence must be >= 0" }
        java.util.UUID.fromString(conversationId)
        val (code, response) = post(
            session,
            serverAddress,
            "/api/e2ee/sync-history/ack",
            JSONObject()
                .put("conversationId", conversationId)
                .put("throughSequence", throughSequence)
                .toString(),
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classifySync(code)
        }
        try {
            SyncAckResult(evicted = JSONObject(response).getInt("evicted"))
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        }
    }

    private fun parseSyncUpload(json: String, createdNew: Boolean): SyncUploadResult {
        try {
            val root = JSONObject(json)
            return SyncUploadResult(
                syncBatchId = java.util.UUID.fromString(root.getString("syncBatchId")),
                acceptedCount = root.getInt("acceptedCount"),
                createdNew = createdNew,
            )
        } catch (e: JSONException) {
            throw EnrollException.Malformed(e)
        } catch (e: IllegalArgumentException) {
            throw EnrollException.Malformed(e)
        }
    }

    private fun parseSyncBatchItem(json: JSONObject, conversationId: String): SyncBatchItem {
        val ciphertext = json.getString("ciphertext")
        com.samvaad.android.crypto.SpikeCryptoMaterial.decodeBase64(ciphertext)
        // The server must only return this conversation's pending rows:
        // a foreign conversationId is a malformed response, never
        // silently relabeled.
        val itemConversationId = json.getString("conversationId")
        if (itemConversationId != conversationId) {
            throw EnrollException.Malformed(
                IllegalArgumentException("sync item for unexpected conversation")
            )
        }
        return SyncBatchItem(
            messageId = json.getString("messageId"),
            conversationId = conversationId,
            sequenceNumber = json.getLong("sequenceNumber"),
            senderDeviceId = json.getString("senderDeviceId"),
            envelopeType = json.getString("envelopeType"),
            ciphertextBase64 = ciphertext,
        )
    }

    /**
     * History-sync classifier. Same taxonomy as [classifyHistory], plus
     * first-class 409: divergent batch-id reuse must converge through a
     * fixed sync batch id, never blind-retry as new content.
     */
    private fun classifySync(code: Int): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        HttpURLConnection.HTTP_BAD_REQUEST -> EnrollException.BadRequest()
        HttpURLConnection.HTTP_FORBIDDEN -> EnrollException.Forbidden()
        HttpURLConnection.HTTP_NOT_FOUND -> EnrollException.NotFound()
        HttpURLConnection.HTTP_CONFLICT -> EnrollException.Conflict()
        else -> EnrollException.ServerRejected()
    }

    private fun parseHistoryItem(json: JSONObject): HistoryItem {
        val ciphertext = json.getString("ciphertext")
        // Transport-encoding gate: history pages feed durable persistence,
        // so an undecodable page fails the whole fetch here. (Mailbox
        // items deliberately defer this to per-entry skip reasons because
        // they are transient and individually skippable.)
        SpikeCryptoMaterial.decodeBase64(ciphertext)
        return HistoryItem(
            messageId = json.getString("messageId"),
            conversationId = json.getString("conversationId"),
            sequenceNumber = json.getLong("sequenceNumber"),
            senderUserId = json.getString("senderUserId"),
            senderDeviceId = json.getString("senderDeviceId"),
            envelopeType = json.getString("envelopeType"),
            ciphertextBase64 = ciphertext,
            serverTimestamp = json.getString("serverTimestamp"),
        )
    }

    private fun parseCursor(json: JSONObject): SyncCursor = SyncCursor(
        conversationId = json.getString("conversationId"),
        throughSequence = json.getLong("throughSequence"),
    )

    /**
     * History/cursor classifier. Documented outcomes: 401 unauthenticated;
     * 404 unknown conversation; 403 non-participant or inactive device;
     * 400 bad pagination/shape; 409 backward or beyond-last cursor move.
     * Anything else is an unexpected rejection.
     */
    private fun classifyHistory(code: Int): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        HttpURLConnection.HTTP_BAD_REQUEST -> EnrollException.BadRequest()
        HttpURLConnection.HTTP_FORBIDDEN -> EnrollException.Forbidden()
        HttpURLConnection.HTTP_NOT_FOUND -> EnrollException.NotFound()
        HttpURLConnection.HTTP_CONFLICT -> EnrollException.Conflict()
        else -> EnrollException.ServerRejected()
    }

    private fun parseSubmit(json: JSONObject, createdNew: Boolean): SubmitMessageResult {        val accepted = json.getJSONArray("acceptedRecipientDevices")
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
        kyberPrekeyId = if (json.isNull("kyberPrekeyId")) {
            null
        } else {
            json.getInt("kyberPrekeyId")
        },
    )

    /**
     * Approve/bind/recovery classifier. Same taxonomy as [classify], plus
     * first-class 404 (unknown device) and 409 (revoked target / bound
     * session / enrollment conflict) so callers can converge through
     * `GET /devices` instead of treating every failure as generic.
     */
    private fun classifyDeviceAction(code: Int, response: String): EnrollException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> EnrollException.Unauthorized()
        HttpURLConnection.HTTP_BAD_REQUEST -> EnrollException.BadRequest()
        HttpURLConnection.HTTP_FORBIDDEN ->
            if (responseReason(response) == RECOVERY_REQUIRED_REASON) {
                EnrollException.RecoveryRequired()
            } else {
                EnrollException.ServerRejected()
            }
        HttpURLConnection.HTTP_NOT_FOUND -> EnrollException.NotFound()
        HttpURLConnection.HTTP_CONFLICT -> EnrollException.Conflict()
        else -> EnrollException.ServerRejected()
    }

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
