package com.samvaad.android

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/**
 * Slice 2 authentication boundary.
 *
 * Minimal HTTP login against the existing server contract
 * (`POST /api/auth/login`). Uses platform-bundled [HttpURLConnection] and
 * `org.json` only — no networking library. The [AuthApi] interface is the
 * seam tests fake; production code never talks to HTTP directly.
 */

/** Outgoing login request. [clientPlatform] is always `ANDROID`. */
data class LoginRequest(
    val serverAddress: String,
    val identifier: String,
    val password: String,
    val clientPlatform: String = "ANDROID",
)

/**
 * Authenticated session. Held ONLY in memory for this slice.
 * Never persisted, never logged, never rendered.
 */
data class AuthSession(
    val identifier: String,
    val accessToken: String,
    val refreshToken: String,
    val sessionId: String,
)

/**
 * The server rejected the login (bad credentials, unknown user, session
 * cap, malformed response, ...). Carries no server text, status codes, or
 * bodies — callers must map it to a fixed safe message.
 */
class AuthRejectedException : IOException()

/**
 * A refresh attempt was rejected (unknown/expired/revoked token or session,
 * malformed response). The stored refresh bundle is unusable; callers must
 * wipe it and return to login. Never thrown for transport failures, which
 * propagate as plain [IOException] and must not wipe anything.
 */
class RefreshRejectedException : IOException()

interface AuthApi {
    /** @throws AuthRejectedException when the server rejects the login. */
    @Throws(IOException::class)
    suspend fun login(request: LoginRequest): AuthSession

    /**
     * POST /api/auth/refresh. Rotates the refresh token server-side: the
     * response carries a NEW refresh token and the SAME sessionId.
     * @throws RefreshRejectedException on any non-200 outcome or malformed body.
     */
    @Throws(IOException::class)
    suspend fun refresh(serverAddress: String, refreshToken: String): RefreshedSession

    /**
     * POST /api/auth/logout. Revokes exactly the calling session; best
     * effort from the caller's perspective — see logout flow docs.
     */
    @Throws(IOException::class)
    suspend fun logout(serverAddress: String, accessToken: String)
}

/** Rotated session material. The access token stays memory-only. */
data class RefreshedSession(
    val accessToken: String,
    val refreshToken: String,
    val sessionId: String,
)

class HttpAuthApi(
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 15_000,
    /**
     * HTTPS enforcement for refresh/logout (login relies on the entry
     * screen's HTTPS-only normalization instead). Always true in
     * production; tests disable it for plaintext loopback stubs.
     */
    private val requireHttps: Boolean = true,
) : AuthApi {

    override suspend fun login(request: LoginRequest): AuthSession =
        withContext(Dispatchers.IO) {
            val connection =
                (URL(request.serverAddress + "/api/auth/login").openConnection()
                        as HttpURLConnection)
                    .apply {
                        requestMethod = "POST"
                        doOutput = true
                        connectTimeout = connectTimeoutMillis
                        readTimeout = readTimeoutMillis
                        setRequestProperty(
                            "Content-Type", "application/json; charset=utf-8"
                        )
                        setRequestProperty("Accept", "application/json")
                    }
            try {
                val body = JSONObject()
                    .put("identifier", request.identifier)
                    .put("password", request.password)
                    .put("installationId", JSONObject.NULL)
                    .put("clientPlatform", request.clientPlatform)
                    .toString()
                connection.outputStream.use {
                    it.write(body.toByteArray(StandardCharsets.UTF_8))
                }
                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    throw AuthRejectedException()
                }
                // Any I/O failure from here on is a transport failure and
                // must propagate as IOException, not rejection.
                val responseBody =
                    connection.inputStream.bufferedReader().use { it.readText() }
                try {
                    val json = JSONObject(responseBody)
                    AuthSession(
                        identifier = request.identifier,
                        accessToken = json.getString("accessToken"),
                        refreshToken = json.getString("refreshToken"),
                        sessionId = json.getString("sessionId"),
                    )
                } catch (e: org.json.JSONException) {
                    throw AuthRejectedException()
                }
            } finally {
                connection.disconnect()
            }
        }

    override suspend fun refresh(
        serverAddress: String,
        refreshToken: String,
    ): RefreshedSession = withContext(Dispatchers.IO) {
        requireHttps(serverAddress)
        val body = JSONObject()
            .put("refreshToken", refreshToken)
            .toString()
        val (code, response) = postJson(serverAddress, "/api/auth/refresh", body, accessToken = null)
        if (code != HttpURLConnection.HTTP_OK) {
            throw RefreshRejectedException()
        }
        try {
            val json = JSONObject(response)
            RefreshedSession(
                accessToken = json.getString("accessToken"),
                refreshToken = json.getString("refreshToken"),
                sessionId = json.getString("sessionId"),
            )
        } catch (e: org.json.JSONException) {
            throw RefreshRejectedException()
        }
    }

    override suspend fun logout(serverAddress: String, accessToken: String): Unit =
        withContext(Dispatchers.IO) {
            requireHttps(serverAddress)
            // Any outcome (including transport failure) is reported to the
            // caller, which wipes local state unconditionally: server
            // revocation is idempotent, so there is nothing to retry.
            postJson(serverAddress, "/api/auth/logout", body = null, accessToken = accessToken)
            Unit
        }

    private fun requireHttps(serverAddress: String) {
        if (requireHttps) {
            require(serverAddress.startsWith("https://")) { "HTTPS only" }
        }
    }

    /**
     * Minimal authenticated POST helper shared by refresh/logout.
     * Returns (status code, body). Transport failures throw [IOException].
     */
    private fun postJson(
        serverAddress: String,
        path: String,
        body: String?,
        accessToken: String?,
    ): Pair<Int, String> {
        val connection =
            (URL(serverAddress + path).openConnection() as HttpURLConnection)
                .apply {
                    requestMethod = "POST"
                    doOutput = body != null
                    connectTimeout = connectTimeoutMillis
                    readTimeout = readTimeoutMillis
                    setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    setRequestProperty("Accept", "application/json")
                    if (accessToken != null) {
                        setRequestProperty("Authorization", "Bearer $accessToken")
                    }
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
        } finally {
            connection.disconnect()
        }
    }
}
