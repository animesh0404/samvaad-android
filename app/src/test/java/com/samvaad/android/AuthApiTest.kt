package com.samvaad.android

import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/**
 * Transport-error classification at the real [HttpAuthApi] boundary,
 * against a minimal loopback socket stub (JVM-only; no Android policy
 * and no extra modules involved):
 *
 * - non-success HTTP response -> [AuthRejectedException]
 * - malformed success body -> [AuthRejectedException]
 * - connect/read I/O failure -> [IOException] (never rejection)
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class AuthApiTest {

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
                // Closed socket during teardown; nothing to serve.
            } finally {
                serverSocket.close()
            }
        }, "stub-auth-server").apply { isDaemon = true }

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
            return requestLine + "\n" + String(bodyChars, 0, read)
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

    private fun request(port: Int) = LoginRequest(
        serverAddress = "http://localhost:$port",
        identifier = "alice",
        password = "s3cr3t!",
    )

    @Test
    fun login_success_parsesSessionAndPostsContractFields() {
        val port = serve(
            200,
            JSONObject()
                .put("accessToken", "access-1")
                .put("refreshToken", "refresh-1")
                .put("expiresIn", 86400)
                .put("sessionId", "11111111-2222-3333-4444-555555555555")
                .toString()
        )

        val session = runBlocking {
            HttpAuthApi().login(request(port))
        }

        assertEquals("alice", session.identifier)
        assertEquals("access-1", session.accessToken)
        assertEquals("refresh-1", session.refreshToken)
        assertEquals("11111111-2222-3333-4444-555555555555", session.sessionId)
        val raw = server!!.lastRequest!!
        assertTrue(raw.startsWith("POST /api/auth/login "))
        val sent = JSONObject(raw.substringAfter("\n"))
        assertEquals("alice", sent.getString("identifier"))
        assertEquals("s3cr3t!", sent.getString("password"))
        assertEquals("ANDROID", sent.getString("clientPlatform"))
        assertTrue(sent.isNull("installationId"))
    }

    @Test
    fun login_nonSuccessResponse_throwsRejected() {
        val port = serve(401, "{}")

        assertThrows(AuthRejectedException::class.java) {
            runBlocking {
                HttpAuthApi().login(request(port))
            }
        }
    }

    @Test
    fun login_malformedSuccessBody_throwsRejected() {
        val port = serve(200, "{not json")

        assertThrows(AuthRejectedException::class.java) {
            runBlocking {
                HttpAuthApi().login(request(port))
            }
        }
    }

    @Test
    fun login_connectionRefused_throwsPlainIOException() {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()

        try {
            runBlocking {
                HttpAuthApi().login(request(port))
            }
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(
                "transport failure must not be converted to rejection",
                e !is AuthRejectedException
            )
        }
    }
}
