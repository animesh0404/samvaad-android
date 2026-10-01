package com.samvaad.android

import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Transport contract for refresh/logout at the real [HttpAuthApi]
 * boundary, against a minimal loopback socket stub (mirrors
 * [AuthApiTest]). No live server.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class AuthRefreshLogoutTest {

    private class StubServer(
        private val status: Int,
        private val body: String,
    ) {
        private val serverSocket =
            ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = serverSocket.localPort
        var lastRequest: String? = null
            private set
        private val thread = Thread({
            try {
                serverSocket.accept().use { socket ->
                    lastRequest = readRequest(socket)
                    writeResponse(socket)
                }
            } catch (_: IOException) {
            } finally {
                serverSocket.close()
            }
        }, "stub-refresh-server").apply { isDaemon = true }

        fun start() = thread.start()

        fun stop() {
            try {
                serverSocket.close()
            } catch (_: IOException) {
            }
            thread.join(5_000)
        }

        private fun readRequest(socket: Socket): String {
            val input = socket.getInputStream().bufferedReader()
            val requestLine = input.readLine() ?: return ""
            val headers = mutableMapOf<String, String>()
            while (true) {
                val line = input.readLine() ?: break
                if (line.isEmpty()) break
                val separator = line.indexOf(':')
                if (separator > 0) {
                    headers[line.substring(0, separator).trim().lowercase()] =
                        line.substring(separator + 1).trim()
                }
            }
            val length = headers["content-length"]?.toIntOrNull() ?: 0
            val bodyChars = CharArray(length)
            var read = 0
            while (read < length) {
                val count = input.read(bodyChars, read, length - read)
                if (count < 0) break
                read += count
            }
            val auth = headers["authorization"]?.let { "\nAuthorization: $it" }.orEmpty()
            return requestLine + auth + "\n" + String(bodyChars, 0, read)
        }

        private fun writeResponse(socket: Socket) {
            val bodyBytes = body.toByteArray(StandardCharsets.UTF_8)
            val out = socket.getOutputStream()
            val head = "HTTP/1.1 $status ${reason(status)}\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: ${bodyBytes.size}\r\n" +
                "Connection: close\r\n" +
                "\r\n"
            out.write(head.toByteArray(StandardCharsets.US_ASCII))
            out.write(bodyBytes)
            out.flush()
        }

        private fun reason(status: Int): String = when (status) {
            200 -> "OK"
            204 -> "No Content"
            401 -> "Unauthorized"
            else -> "Error"
        }
    }

    private var server: StubServer? = null

    @After
    fun stopServer() {
        server?.stop()
        server = null
    }

    private fun serve(status: Int, body: String): Int {
        val stub = StubServer(status, body)
        stub.start()
        server = stub
        return stub.port
    }

    private fun refreshBody() = JSONObject()
        .put("accessToken", "access-new")
        .put("refreshToken", "refresh-new")
        .put("expiresIn", 86400)
        .put("sessionId", "11111111-2222-3333-4444-555555555555")
        .toString()

    @Test
    fun refresh_postsToken_parsesRotatedSession() {
        val port = serve(200, refreshBody())
        val refreshed = runBlocking {
            HttpAuthApi(requireHttps = false).refresh("http://localhost:$port", "refresh-old")
        }
        assertEquals("access-new", refreshed.accessToken)
        assertEquals("refresh-new", refreshed.refreshToken)
        assertEquals("11111111-2222-3333-4444-555555555555", refreshed.sessionId)
        val raw = server!!.lastRequest!!
        assertTrue(raw.startsWith("POST /api/auth/refresh "))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        assertEquals("refresh-old", sent.getString("refreshToken"))
        // No authorization header on the refresh call itself.
        assertFalse(raw.contains("Authorization:"))
    }

    @Test
    fun refresh_rejectedStatus_mapsToRefreshRejected() {
        val port = serve(401, "{}")
        assertThrows(RefreshRejectedException::class.java) {
            runBlocking {
                HttpAuthApi(requireHttps = false).refresh("http://localhost:$port", "refresh-old")
            }
        }
    }

    @Test
    fun refresh_malformedBody_mapsToRefreshRejected() {
        val port = serve(200, "{not json")
        assertThrows(RefreshRejectedException::class.java) {
            runBlocking {
                HttpAuthApi(requireHttps = false).refresh("http://localhost:$port", "refresh-old")
            }
        }
    }

    @Test
    fun refresh_httpScheme_rejectedByDefault() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpAuthApi().refresh("http://localhost:1", "refresh-old")
            }
        }
    }

    @Test
    fun refresh_connectionRefused_propagatesTransport() {        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        try {
            runBlocking {
                HttpAuthApi(requireHttps = false).refresh("http://localhost:$port", "refresh-old")
            }
            org.junit.Assert.fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e !is RefreshRejectedException)
        }
    }

    @Test
    fun logout_postsWithBearerAuth() {
        val port = serve(204, "")
        runBlocking {
            HttpAuthApi(requireHttps = false).logout("http://localhost:$port", "access-1")
        }
        val raw = server!!.lastRequest!!
        assertTrue(raw.startsWith("POST /api/auth/logout "))
        assertTrue(raw.contains("Authorization: Bearer access-1"))
    }

    @Test
    fun logout_serverError_stillReturns() {
        val port = serve(500, "{}")
        // The API surfaces the outcome; the caller decides cleanup.
        // A 500 response body read must not throw here.
        runBlocking {
            HttpAuthApi(requireHttps = false).logout("http://localhost:$port", "access-1")
        }
    }
}
