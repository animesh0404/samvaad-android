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

interface AuthApi {
    /** @throws AuthRejectedException when the server rejects the login. */
    @Throws(IOException::class)
    suspend fun login(request: LoginRequest): AuthSession
}

class HttpAuthApi(
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 15_000,
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
}
