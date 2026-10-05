package com.samvaad.android.friends

import com.samvaad.android.AuthSession
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * HTTP friend-request boundary: `HttpURLConnection` + `org.json`,
 * HTTPS-only, no networking library. Mirrors `HttpE2eeDeviceApi`
 * conventions (timeouts, `disconnect()` in `finally`, transport
 * failures as [IOException], Bearer auth).
 *
 * Server error bodies are never surfaced — only status codes map to
 * the [FriendException] taxonomy.
 */
class HttpFriendsApi(
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 15_000,
    /**
     * HTTPS enforcement. Always true in production; tests disable it to
     * run against a plaintext loopback stub (no TLS stack involved).
     */
    private val requireHttps: Boolean = true,
) : FriendsApi {

    override suspend fun lookupUser(
        session: AuthSession,
        serverAddress: String,
        username: String,
    ): FriendEntry = withContext(Dispatchers.IO) {
        val encoded = URLEncoder.encode(username, StandardCharsets.UTF_8.name())
        val (code, response) = get(session, serverAddress, "/api/users/lookup?username=$encoded")
        if (code != HttpURLConnection.HTTP_OK) {
            throw classify(code)
        }
        try {
            parseFriend(JSONObject(response))
        } catch (e: JSONException) {
            throw FriendException.Transport(e)
        }
    }

    override suspend fun sendRequest(
        session: AuthSession,
        serverAddress: String,
        username: String,
    ): FriendRequestRecord = withContext(Dispatchers.IO) {
        val body = JSONObject().put("username", username).toString()
        val (code, response) = post(session, serverAddress, "/api/friend-requests", body)
        if (code != HttpURLConnection.HTTP_CREATED) {
            throw classify(code)
        }
        try {
            parseRequest(JSONObject(response))
        } catch (e: JSONException) {
            throw FriendException.Transport(e)
        }
    }

    override suspend fun listIncoming(
        session: AuthSession,
        serverAddress: String,
    ): List<FriendRequestRecord> = withContext(Dispatchers.IO) {
        getRequestList(session, serverAddress, "/api/friend-requests/incoming")
    }

    override suspend fun listOutgoing(
        session: AuthSession,
        serverAddress: String,
    ): List<FriendRequestRecord> = withContext(Dispatchers.IO) {
        getRequestList(session, serverAddress, "/api/friend-requests/outgoing")
    }

    override suspend fun acceptRequest(
        session: AuthSession,
        serverAddress: String,
        requestId: String,
    ): FriendRequestRecord = withContext(Dispatchers.IO) {
        respond(session, serverAddress, requestId, "accept")
    }

    override suspend fun rejectRequest(
        session: AuthSession,
        serverAddress: String,
        requestId: String,
    ): FriendRequestRecord = withContext(Dispatchers.IO) {
        respond(session, serverAddress, requestId, "reject")
    }

    override suspend fun cancelRequest(
        session: AuthSession,
        serverAddress: String,
        requestId: String,
    ): FriendRequestRecord = withContext(Dispatchers.IO) {
        respond(session, serverAddress, requestId, "cancel")
    }

    override suspend fun listFriends(
        session: AuthSession,
        serverAddress: String,
    ): List<FriendEntry> = withContext(Dispatchers.IO) {
        val (code, response) = get(session, serverAddress, "/api/friends")
        if (code != HttpURLConnection.HTTP_OK) {
            throw classify(code)
        }
        try {
            val array = JSONArray(response)
            List(array.length()) { i -> parseFriend(array.getJSONObject(i)) }
        } catch (e: JSONException) {
            throw FriendException.Transport(e)
        }
    }

    private fun getRequestList(
        session: AuthSession,
        serverAddress: String,
        path: String,
    ): List<FriendRequestRecord> {
        val (code, response) = get(session, serverAddress, path)
        if (code != HttpURLConnection.HTTP_OK) {
            throw classify(code)
        }
        try {
            val array = JSONArray(response)
            return List(array.length()) { i -> parseRequest(array.getJSONObject(i)) }
        } catch (e: JSONException) {
            throw FriendException.Transport(e)
        }
    }

    private fun respond(
        session: AuthSession,
        serverAddress: String,
        requestId: String,
        action: String,
    ): FriendRequestRecord {
        // Empty JSON body: the transition is fully addressed by the URL.
        val (code, response) = post(
            session, serverAddress, "/api/friend-requests/$requestId/$action", "{}"
        )
        if (code != HttpURLConnection.HTTP_OK) {
            throw classify(code)
        }
        try {
            return parseRequest(JSONObject(response))
        } catch (e: JSONException) {
            throw FriendException.Transport(e)
        }
    }

    private fun parseRequest(json: JSONObject): FriendRequestRecord = FriendRequestRecord(
        requestId = json.getString("requestId"),
        senderUserId = json.getString("senderUserId"),
        senderUsername = json.getString("senderUsername"),
        recipientUserId = json.getString("recipientUserId"),
        recipientUsername = json.getString("recipientUsername"),
        status = json.getString("status"),
        createdAt = json.optString("createdAt", null),
        respondedAt = json.optString("respondedAt", null),
    )

    private fun parseFriend(json: JSONObject): FriendEntry = FriendEntry(
        userId = json.getString("userId"),
        username = json.getString("username"),
    )

    /**
     * Friend-request classifier. 403 is self-request (send) or wrong
     * party (accept/reject/cancel); 404 is unknown user or unknown
     * request; 409 is duplicate-pending / already-friends /
     * no-longer-pending.
     */
    private fun classify(code: Int): FriendException = when (code) {
        HttpURLConnection.HTTP_UNAUTHORIZED -> FriendException.Unauthorized()
        HttpURLConnection.HTTP_BAD_REQUEST -> FriendException.BadRequest()
        HttpURLConnection.HTTP_FORBIDDEN -> FriendException.Forbidden()
        HttpURLConnection.HTTP_NOT_FOUND -> FriendException.NotFound()
        HttpURLConnection.HTTP_CONFLICT -> FriendException.Conflict()
        else -> FriendException.ServerRejected()
    }

    private fun post(
        session: AuthSession,
        serverAddress: String,
        path: String,
        body: String,
    ): Pair<Int, String> = request(session, serverAddress, path, "POST", body)

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
            throw FriendException.Transport(e)
        } finally {
            connection.disconnect()
        }
    }
}
