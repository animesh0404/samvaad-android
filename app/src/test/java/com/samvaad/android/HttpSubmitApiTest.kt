package com.samvaad.android

import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.HttpE2eeDeviceApi
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
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
 * Transport contract for message submission at the real
 * [HttpE2eeDeviceApi] boundary, against a minimal loopback socket stub
 * (mirrors [HttpSessionDirectoryApiTest]): exact POST JSON shape,
 * Bearer auth, UUID/base64 fields, 201/200 distinction, status taxonomy,
 * and failure classification. No live server, no crypto.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpSubmitApiTest {

    private class StubServer(
        private val responses: MutableList<Pair<Int, String>>,
    ) {
        private val serverSocket =
            ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = serverSocket.localPort
        val requests = mutableListOf<String>()
        private val thread = Thread({
            try {
                repeat(responses.size) {
                    serverSocket.accept().use { socket ->
                        requests.add(readRequest(socket))
                        val (status, body) = responses[it]
                        writeResponse(socket, status, body)
                    }
                }
            } catch (_: IOException) {
            } finally {
                serverSocket.close()
            }
        }, "stub-submit-server").apply { isDaemon = true }

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
            val auth = headers["authorization"].orEmpty()
            return requestLine + "\nAuthorization: " + auth + "\n" + String(bodyChars, 0, read)
        }

        private fun writeResponse(socket: Socket, status: Int, body: String) {
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
            201 -> "Created"
            400 -> "Bad Request"
            401 -> "Unauthorized"
            403 -> "Forbidden"
            404 -> "Not Found"
            409 -> "Conflict"
            500 -> "Server Error"
            else -> "Error"
        }
    }

    private var server: StubServer? = null

    @After
    fun stopServer() {
        server?.stop()
        server = null
    }

    private fun serve(vararg responses: Pair<Int, String>): Int {
        val stub = StubServer(responses.toMutableList())
        stub.start()
        server = stub
        return stub.port
    }

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )

    private fun envelope() = MessageEnvelopeSubmit(
        senderDeviceId = "11111111-1111-1111-1111-111111111111",
        recipientDeviceId = "22222222-2222-3333-4444-555555555555",
        envelopeType = "PREKEY_INIT",
        ciphertextBase64 = java.util.Base64.getEncoder().encodeToString("wire-bytes".toByteArray()),
    )

    private fun successBody(): String = JSONObject()
        .put("messageId", "33333333-3333-3333-3333-333333333333")
        .put("conversationId", "44444444-4444-4444-4444-444444444444")
        .put("sequenceNumber", 7)
        .put("serverTimestamp", "2026-10-02T10:00:00")
        .put("acceptedRecipientDevices", JSONArray(listOf("22222222-2222-3333-4444-555555555555")))
        .toString()

    @Test
    fun submit_postsExactJsonShape_withBearerAuth() {
        val port = serve(201 to successBody())
        val requestId = UUID.randomUUID()
        val result = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .submitMessage(session, "http://localhost:$port", requestId, listOf(envelope()))
        }
        assertEquals("33333333-3333-3333-3333-333333333333", result.messageId)
        assertEquals("44444444-4444-4444-4444-444444444444", result.conversationId)
        assertEquals(7L, result.sequenceNumber)
        assertEquals("2026-10-02T10:00:00", result.serverTimestamp)
        assertEquals(listOf("22222222-2222-3333-4444-555555555555"), result.acceptedRecipientDevices)
        assertTrue(result.createdNew)

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/messages "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        // Exact contract: two top-level keys, four envelope keys, nothing else.
        assertEquals(setOf("messageRequestId", "envelopes"), sent.keys().asSequence().toSet())
        assertEquals(requestId.toString(), sent.getString("messageRequestId"))
        UUID.fromString(sent.getString("messageRequestId"))
        val envs = sent.getJSONArray("envelopes")
        assertEquals(1, envs.length())
        val env = envs.getJSONObject(0)
        assertEquals(
            setOf("senderDeviceId", "recipientDeviceId", "envelopeType", "ciphertext"),
            env.keys().asSequence().toSet(),
        )
        assertEquals("11111111-1111-1111-1111-111111111111", env.getString("senderDeviceId"))
        assertEquals("22222222-2222-3333-4444-555555555555", env.getString("recipientDeviceId"))
        assertEquals("PREKEY_INIT", env.getString("envelopeType"))
        // Standard Base64 round-trips through the wire shape.
        assertEquals(
            "wire-bytes",
            String(java.util.Base64.getDecoder().decode(env.getString("ciphertext"))),
        )
    }

    @Test
    fun submit_200Replay_parsesCreatedNewFalse() {
        val port = serve(200 to successBody())
        val result = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
        }
        assertFalse(result.createdNew)
        assertEquals("33333333-3333-3333-3333-333333333333", result.messageId)
    }

    @Test
    fun submit_400_mapsToBadRequest() {
        val port = serve(400 to "{}")
        assertThrows(EnrollException.BadRequest::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_403_mapsToForbidden() {
        val port = serve(403 to "{}")
        assertThrows(EnrollException.Forbidden::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_404_mapsToNotFound() {
        val port = serve(404 to "{}")
        assertThrows(EnrollException.NotFound::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_409_mapsToConflict() {
        val port = serve(409 to "{}")
        assertThrows(EnrollException.Conflict::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_500_mapsToServerRejected() {
        val port = serve(500 to "{}")
        assertThrows(EnrollException.ServerRejected::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_malformedSuccess_mapsToMalformed() {
        val port = serve(201 to "{not json")
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_connectionRefused_mapsToTransport() {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        assertThrows(EnrollException.Transport::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .submitMessage(session, "http://localhost:$port", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }

    @Test
    fun submit_httpScheme_rejectedLocally() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi()
                    .submitMessage(session, "http://localhost:1", UUID.randomUUID(), listOf(envelope()))
            }
        }
    }
}
