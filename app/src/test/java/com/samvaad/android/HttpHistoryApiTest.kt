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
 * Transport contract for history fetch + sync cursor at the real
 * [HttpE2eeDeviceApi] boundary, against a minimal loopback socket stub
 * (mirrors [HttpInboxApiTest]): exact paths/query/body, Bearer auth,
 * response parsing, status taxonomy, and failure classification. No live
 * server, no crypto. Cursor methods are explicit and independent: this
 * suite also proves no fetch mutates cursor state (there is no such
 * call — fetch and cursor are separate requests).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpHistoryApiTest {

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
        }, "stub-history-server").apply { isDaemon = true }

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
            404 -> "Not Found"
            409 -> "Conflict"
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
    private val conversationId = "44444444-4444-4444-4444-444444444444"

    private fun historyItemJson(
        messageId: String = "33333333-3333-3333-3333-333333333333",
        sequenceNumber: Long = 7L,
    ): JSONObject = JSONObject()
        .put("messageId", messageId)
        .put("conversationId", conversationId)
        .put("sequenceNumber", sequenceNumber)
        .put("senderUserId", "55555555-5555-5555-5555-555555555555")
        .put("senderDeviceId", "22222222-2222-3333-4444-555555555555")
        .put("envelopeType", "RATCHET")
        .put("ciphertext", java.util.Base64.getEncoder().encodeToString("wire".toByteArray()))
        .put("serverTimestamp", "2026-10-02T10:00:00")

    private fun cursorJson(through: Long = 7L): String = JSONObject()
        .put("conversationId", conversationId)
        .put("throughSequence", through)
        .toString()

    // ---- history ----

    @Test
    fun history_getsExactPath_withBearerAuth() {
        val port = serve(200 to JSONArray(listOf(historyItemJson())).toString())
        val items = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .fetchHistory(session, "http://localhost:$port", conversationId, 0L, 20)
        }
        assertEquals(1, items.size)
        val item = items.single()
        assertEquals("33333333-3333-3333-3333-333333333333", item.messageId)
        assertEquals(conversationId, item.conversationId)
        assertEquals(7L, item.sequenceNumber)
        assertEquals("55555555-5555-5555-5555-555555555555", item.senderUserId)
        assertEquals("22222222-2222-3333-4444-555555555555", item.senderDeviceId)
        assertEquals("RATCHET", item.envelopeType)
        assertEquals("2026-10-02T10:00:00", item.serverTimestamp)
        assertEquals(
            "wire",
            String(java.util.Base64.getDecoder().decode(item.ciphertextBase64)),
        )
        val raw = server!!.requests.single()
        assertTrue(
            raw.startsWith("GET /api/e2ee/conversations/$conversationId/messages?afterSequence=0&limit=20 ")
        )
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
    }

    @Test
    fun history_afterSequenceAndLimit_encoded() {
        val port = serve(200 to "[]")
        runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .fetchHistory(session, "http://localhost:$port", conversationId, 42L, 100)
        }
        assertTrue(
            server!!.requests.single().startsWith(
                "GET /api/e2ee/conversations/$conversationId/messages?afterSequence=42&limit=100 "
            )
        )
    }

    @Test
    fun history_emptyArray_parsesToEmptyList() {
        val port = serve(200 to "[]")
        val items = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .fetchHistory(session, "http://localhost:$port", conversationId, 0L, 20)
        }
        assertTrue(items.isEmpty())
    }

    @Test
    fun history_malformedJson_mapsToMalformed() {
        val port = serve(200 to "{not json")
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:$port", conversationId, 0L, 20)
            }
        }
    }

    @Test
    fun history_badBase64_mapsToMalformed() {
        // The page carries JSON-valid but Base64-invalid ciphertext: the
        // fetch fails closed instead of handing undecodable bytes toward
        // durable persistence.
        val bad = historyItemJson().put("ciphertext", "!!!not-base64!!!")
        val port = serve(200 to JSONArray(listOf(bad)).toString())
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:$port", conversationId, 0L, 20)
            }
        }
    }

    @Test
    fun history_statuses_mapped() {
        suspend fun statusThrows(status: Int, expected: Class<out EnrollException>) {
            val port = serve(status to "{}")
            try {
                runBlocking {
                    HttpE2eeDeviceApi(requireHttps = false)
                        .fetchHistory(session, "http://localhost:$port", conversationId, 0L, 20)
                }
            } catch (e: EnrollException) {
                assertTrue(expected.isInstance(e))
                return
            }
            throw AssertionError("expected $expected for HTTP $status")
        }
        runBlocking {
            statusThrows(401, EnrollException.Unauthorized::class.java)
            statusThrows(403, EnrollException.Forbidden::class.java)
            statusThrows(404, EnrollException.NotFound::class.java)
            statusThrows(400, EnrollException.BadRequest::class.java)
        }
    }

    @Test
    fun history_connectionRefused_mapsToTransport() {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        assertThrows(EnrollException.Transport::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:$port", conversationId, 0L, 20)
            }
        }
    }

    @Test
    fun history_invalidArgs_rejectedLocally() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:1", "", 0L, 20)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:1", conversationId, -1L, 20)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:1", conversationId, 0L, 0)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:1", conversationId, 0L, 101)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchHistory(session, "http://localhost:1", "not-a-uuid", 0L, 20)
            }
        }
    }

    // ---- cursor GET ----

    @Test
    fun cursorGet_decodesValue() {
        val port = serve(200 to cursorJson(7L))
        val cursor = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .getSyncCursor(session, "http://localhost:$port", conversationId)
        }
        assertEquals(conversationId, cursor.conversationId)
        assertEquals(7L, cursor.throughSequence)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("GET /api/e2ee/sync?conversationId=$conversationId "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
    }

    @Test
    fun cursorGet_absentCursor_readsZero() {
        // The server answers 200 with throughSequence 0 when no cursor
        // row exists; the client decodes the value as given.
        val port = serve(200 to cursorJson(0L))
        val cursor = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .getSyncCursor(session, "http://localhost:$port", conversationId)
        }
        assertEquals(0L, cursor.throughSequence)
    }

    @Test
    fun cursorGet_malformed_mapsToMalformed() {
        val port = serve(200 to "{oops")
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .getSyncCursor(session, "http://localhost:$port", conversationId)
            }
        }
    }

    @Test
    fun cursorGet_401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .getSyncCursor(session, "http://localhost:$port", conversationId)
            }
        }
    }

    // ---- cursor PUT ----

    @Test
    fun cursorPut_postsExactBody_decodesResponse() {
        val port = serve(200 to cursorJson(9L))
        val cursor = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .advanceSyncCursor(session, "http://localhost:$port", conversationId, 9L)
        }
        assertEquals(conversationId, cursor.conversationId)
        assertEquals(9L, cursor.throughSequence)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("PUT /api/e2ee/sync "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        assertEquals(setOf("conversationId", "throughSequence"), sent.keys().asSequence().toSet())
        assertEquals(conversationId, sent.getString("conversationId"))
        // Long-compatible value, exact.
        assertEquals(9L, sent.getLong("throughSequence"))
    }

    @Test
    fun cursorPut_negativeThrough_rejectedLocally() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .advanceSyncCursor(session, "http://localhost:1", conversationId, -1L)
            }
        }
    }

    @Test
    fun cursorPut_409_mapsToConflict() {
        // Backward or beyond-last moves: server rejects, client surfaces
        // distinctly so the reconciler can re-read instead of retrying.
        val port = serve(409 to "{}")
        assertThrows(EnrollException.Conflict::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .advanceSyncCursor(session, "http://localhost:$port", conversationId, 3L)
            }
        }
    }

    @Test
    fun cursorPut_connectionRefused_mapsToTransport() {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        assertThrows(EnrollException.Transport::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .advanceSyncCursor(session, "http://localhost:$port", conversationId, 3L)
            }
        }
    }

    // ---- separation ----

    @Test
    fun historyFetch_issuesNoCursorRequest() {
        val port = serve(200 to "[]")
        runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .fetchHistory(session, "http://localhost:$port", conversationId, 0L, 20)
        }
        // Exactly one request went out, and it was the history GET —
        // cursor state is never touched implicitly.
        assertEquals(1, server!!.requests.size)
        assertTrue(server!!.requests.single().startsWith("GET /api/e2ee/conversations/"))
    }
}
