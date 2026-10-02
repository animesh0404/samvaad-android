package com.samvaad.android

import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.HttpE2eeDeviceApi
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
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Transport contract for mailbox fetch + ACK at the real
 * [HttpE2eeDeviceApi] boundary, against a minimal loopback socket stub
 * (mirrors [HttpSubmitApiTest]): exact paths/query/body, Bearer auth,
 * response parsing, status taxonomy, and failure classification. No live
 * server, no crypto.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpInboxApiTest {

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
        }, "stub-inbox-server").apply { isDaemon = true }

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
            400 -> "Bad Request"
            401 -> "Unauthorized"
            403 -> "Forbidden"
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

    private fun itemJson(
        messageId: String = "33333333-3333-3333-3333-333333333333",
        envelopeType: String = "PREKEY_INIT",
    ): JSONObject = JSONObject()
        .put("messageId", messageId)
        .put("conversationId", "44444444-4444-4444-4444-444444444444")
        .put("sequenceNumber", 7)
        .put("senderUserId", "55555555-5555-5555-5555-555555555555")
        .put("senderDeviceId", "22222222-2222-3333-4444-555555555555")
        .put("envelopeType", envelopeType)
        .put("ciphertext", java.util.Base64.getEncoder().encodeToString("wire".toByteArray()))
        .put("serverTimestamp", "2026-10-02T10:00:00")

    @Test
    fun fetch_getsExactPath_withBearerAuth() {
        val port = serve(200 to JSONArray(listOf(itemJson())).toString())
        val items = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port", 20)
        }
        assertEquals(1, items.size)
        val item = items.single()
        assertEquals("33333333-3333-3333-3333-333333333333", item.messageId)
        assertEquals("44444444-4444-4444-4444-444444444444", item.conversationId)
        assertEquals(7L, item.sequenceNumber)
        assertEquals("55555555-5555-5555-5555-555555555555", item.senderUserId)
        assertEquals("22222222-2222-3333-4444-555555555555", item.senderDeviceId)
        assertEquals("PREKEY_INIT", item.envelopeType)
        assertEquals("2026-10-02T10:00:00", item.serverTimestamp)
        assertEquals(
            "wire",
            String(java.util.Base64.getDecoder().decode(item.ciphertextBase64)),
        )
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("GET /api/e2ee/mailbox?limit=20 "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
    }

    @Test
    fun fetch_defaultLimit_is20() {
        val port = serve(200 to "[]")
        runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port")
        }
        assertTrue(server!!.requests.single().startsWith("GET /api/e2ee/mailbox?limit=20 "))
    }

    @Test
    fun fetch_customLimit_inPath() {
        val port = serve(200 to "[]")
        runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port", 100)
        }
        assertTrue(server!!.requests.single().startsWith("GET /api/e2ee/mailbox?limit=100 "))
    }

    @Test
    fun fetch_emptyArray_parsesToEmptyList() {
        val port = serve(200 to "[]")
        val items = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port", 20)
        }
        assertTrue(items.isEmpty())
    }

    @Test
    fun fetch_multipleItems_preserveOrder() {
        val port = serve(200 to JSONArray(listOf(
            itemJson(messageId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            itemJson(messageId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", envelopeType = "RATCHET"),
        )).toString())
        val items = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port", 20)
        }
        assertEquals(2, items.size)
        assertEquals("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", items[0].messageId)
        assertEquals("RATCHET", items[1].envelopeType)
    }

    @Test
    fun fetch_malformedJson_mapsToMalformed() {
        val port = serve(200 to "{not json")
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port", 20)
            }
        }
    }

    @Test
    fun fetch_401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port", 20)
            }
        }
    }

    @Test
    fun fetch_connectionRefused_mapsToTransport() {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        assertThrows(EnrollException.Transport::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:$port", 20)
            }
        }
    }

    @Test
    fun fetch_invalidLimit_rejectedLocally() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:1", 0)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).fetchMailbox(session, "http://localhost:1", 101)
            }
        }
    }

    @Test
    fun ack_postsExactBody_parsesCount() {
        val port = serve(200 to JSONObject().put("acknowledged", 1).toString())
        val id = UUID.randomUUID()
        val count = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).ackMailbox(session, "http://localhost:$port", listOf(id))
        }
        assertEquals(1, count)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/mailbox/ack "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        assertEquals(setOf("messageIds"), sent.keys().asSequence().toSet())
        val ids = sent.getJSONArray("messageIds")
        assertEquals(1, ids.length())
        assertEquals(id.toString(), ids.getString(0))
    }

    @Test
    fun ack_zero_parses() {
        val port = serve(200 to JSONObject().put("acknowledged", 0).toString())
        val count = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .ackMailbox(session, "http://localhost:$port", listOf(UUID.randomUUID()))
        }
        assertEquals(0, count)
    }

    @Test
    fun ack_malformedResponse_mapsToMalformed() {
        val port = serve(200 to "{oops")
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .ackMailbox(session, "http://localhost:$port", listOf(UUID.randomUUID()))
            }
        }
    }

    @Test
    fun ack_401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .ackMailbox(session, "http://localhost:$port", listOf(UUID.randomUUID()))
            }
        }
    }

    @Test
    fun ack_403_mapsToForbidden() {
        val port = serve(403 to "{}")
        assertThrows(EnrollException.Forbidden::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .ackMailbox(session, "http://localhost:$port", listOf(UUID.randomUUID()))
            }
        }
    }

    @Test
    fun ack_connectionRefused_mapsToTransport() {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        assertThrows(EnrollException.Transport::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .ackMailbox(session, "http://localhost:$port", listOf(UUID.randomUUID()))
            }
        }
    }
}
