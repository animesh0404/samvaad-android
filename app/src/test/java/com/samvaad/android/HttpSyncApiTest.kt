package com.samvaad.android

import com.samvaad.android.enroll.HttpE2eeDeviceApi
import com.samvaad.android.enroll.SyncBatchItem
import com.samvaad.android.enroll.SyncUploadRequest
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
 * History-sync HTTP transport tests against a loopback stub: request
 * shapes, status mapping (201 new / 200 replay / 400 / 403 / 404 /
 * 409), response parsing, malformed bodies, and transport failure.
 * Plaintext HTTP stubs only (`requireHttps = false`); production
 * always requires HTTPS.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpSyncApiTest {

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
        }, "stub-sync-server").apply { isDaemon = true }

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
    private val batchId = UUID.fromString("55555555-5555-5555-5555-555555555555")

    private fun uploadBody(): String = JSONObject()
        .put("syncBatchId", batchId.toString())
        .put("recipientDeviceId", "66666666-6666-6666-6666-666666666666")
        .put("conversationId", conversationId)
        .put("fromSequence", 0)
        .put("frontier", 1)
        .put("items", JSONArray().put(
            JSONObject()
                .put("messageId", "77777777-7777-7777-7777-777777777777")
                .put("sequenceNumber", 1)
                .put("senderDeviceId", "88888888-8888-8888-8888-888888888888")
                .put("envelopeType", "RATCHET")
                .put("ciphertext", "eA==")
        ))
        .toString()

    private fun uploadRequest() = SyncUploadRequest(
        syncBatchId = batchId,
        recipientDeviceId = "66666666-6666-6666-6666-666666666666",
        conversationId = conversationId,
        fromSequence = 0,
        frontier = 1,
        items = listOf(
            SyncBatchItem(
                messageId = "77777777-7777-7777-7777-777777777777",
                conversationId = conversationId,
                sequenceNumber = 1,
                senderDeviceId = "88888888-8888-8888-8888-888888888888",
                envelopeType = "RATCHET",
                ciphertextBase64 = "eA==",
            )
        ),
    )

    private fun uploadResponse(createdNew: Boolean) = JSONObject()
        .put("syncBatchId", batchId.toString())
        .put("acceptedCount", 1)
        .put("createdNew", createdNew)
        .toString()

    @Test
    fun upload_newBatch_returns201ShapeAndPostsContract() {
        val port = serve(201 to uploadResponse(true))
        val result = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .uploadSyncBatch(session, "http://localhost:$port", uploadRequest())
        }
        assertTrue(result.createdNew)
        assertEquals(1, result.acceptedCount)
        assertEquals(batchId, result.syncBatchId)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/sync-history/batches "))
        val sent = JSONObject(raw.substringAfter("\n"))
        assertEquals(batchId.toString(), sent.getString("syncBatchId"))
        assertEquals(conversationId, sent.getString("conversationId"))
        assertEquals(0, sent.getLong("fromSequence").toInt())
        assertEquals(1, sent.getJSONArray("items").length())
        val item = sent.getJSONArray("items").getJSONObject(0)
        assertEquals("RATCHET", item.getString("envelopeType"))
    }

    @Test
    fun upload_replay_returns200NotCreated() {
        val port = serve(200 to uploadResponse(false))
        val result = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .uploadSyncBatch(session, "http://localhost:$port", uploadRequest())
        }
        assertFalse(result.createdNew)
    }

    @Test
    fun upload_conflict_maps409() {
        val port = serve(409 to "{}")
        assertThrows(com.samvaad.android.enroll.EnrollException.Conflict::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .uploadSyncBatch(session, "http://localhost:$port", uploadRequest())
            }
        }
    }

    @Test
    fun upload_forbidden_maps403() {
        val port = serve(403 to "{}")
        assertThrows(com.samvaad.android.enroll.EnrollException.Forbidden::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .uploadSyncBatch(session, "http://localhost:$port", uploadRequest())
            }
        }
    }

    @Test
    fun upload_notFound_maps404() {
        val port = serve(404 to "{}")
        assertThrows(com.samvaad.android.enroll.EnrollException.NotFound::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .uploadSyncBatch(session, "http://localhost:$port", uploadRequest())
            }
        }
    }

    @Test
    fun upload_badRequest_maps400() {
        val port = serve(400 to "{}")
        assertThrows(com.samvaad.android.enroll.EnrollException.BadRequest::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .uploadSyncBatch(session, "http://localhost:$port", uploadRequest())
            }
        }
    }

    @Test
    fun upload_malformedBody_mapsTransport() {
        val port = serve(201 to "{not json")
        assertThrows(com.samvaad.android.enroll.EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .uploadSyncBatch(session, "http://localhost:$port", uploadRequest())
            }
        }
    }

    @Test
    fun upload_emptyItems_rejectedLocally() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .uploadSyncBatch(
                        session, "http://localhost:1",
                        uploadRequest().copy(items = emptyList())
                    )
            }
        }
    }

    @Test
    fun fetch_returnsItems() {
        val body = JSONArray().put(
            JSONObject()
                .put("messageId", "77777777-7777-7777-7777-777777777777")
                .put("conversationId", conversationId)
                .put("sequenceNumber", 3)
                .put("senderDeviceId", "88888888-8888-8888-8888-888888888888")
                .put("envelopeType", "PREKEY_INIT")
                .put("ciphertext", "eA==")
        ).toString()
        val port = serve(200 to body)
        val items = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .fetchSyncBatch(session, "http://localhost:$port", conversationId, 2L, 20)
        }
        assertEquals(1, items.size)
        assertEquals(3L, items[0].sequenceNumber)
        assertEquals("PREKEY_INIT", items[0].envelopeType)
        assertEquals(conversationId, items[0].conversationId)
        val raw = server!!.requests.single()
        assertTrue(
            raw.startsWith(
                "GET /api/e2ee/sync-history/batches?conversationId=$conversationId" +
                    "&afterSequence=2&limit=20 "
            )
        )
    }

    @Test
    fun fetch_emptyArray_returnsEmpty() {
        val port = serve(200 to "[]")
        val items = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .fetchSyncBatch(session, "http://localhost:$port", conversationId, 0L, 20)
        }
        assertTrue(items.isEmpty())
    }

    @Test
    fun fetch_wrongConversation_rejected() {
        val body = JSONArray().put(
            JSONObject()
                .put("messageId", "77777777-7777-7777-7777-777777777777")
                .put("conversationId", "99999999-9999-9999-9999-999999999999")
                .put("sequenceNumber", 3)
                .put("senderDeviceId", "88888888-8888-8888-8888-888888888888")
                .put("envelopeType", "RATCHET")
                .put("ciphertext", "eA==")
        ).toString()
        val port = serve(200 to body)
        assertThrows(com.samvaad.android.enroll.EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchSyncBatch(session, "http://localhost:$port", conversationId, 0L, 20)
            }
        }
    }

    @Test
    fun ack_returnsEvicted() {
        val port = serve(200 to JSONObject().put("evicted", 4).toString())
        val result = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .ackSync(session, "http://localhost:$port", conversationId, 9L)
        }
        assertEquals(4, result.evicted)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/sync-history/ack "))
        val sent = JSONObject(raw.substringAfter("\n"))
        assertEquals(9, sent.getLong("throughSequence").toInt())
    }

    @Test
    fun listConversations_returnsIds() {
        val body = JSONArray().put(
            JSONObject()
                .put("conversationId", conversationId)
                .put("otherParticipantUserId", "99999999-9999-9999-9999-999999999999")
                .put("otherParticipantUsername", "bob")
                .put("lastSequenceNumber", 7)
        ).toString()
        val port = serve(200 to body)
        val ids = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .listConversations(session, "http://localhost:$port", 20)
        }
        assertEquals(listOf(conversationId), ids)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("GET /api/conversations/direct?limit=20&offset=0 "))
    }

    @Test
    fun sync_httpsRequiredByDefault() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi()
                    .fetchSyncBatch(session, "http://localhost:1", conversationId, 0L, 20)
            }
        }
    }

    @Test
    fun sync_transportFailure_propagates() {
        val socket = java.net.ServerSocket(0)
        val port = socket.localPort
        socket.close()
        try {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .fetchSyncBatch(session, "http://localhost:$port", conversationId, 0L, 20)
            }
            org.junit.Assert.fail("expected transport failure")
        } catch (e: IOException) {
            assertTrue(e is com.samvaad.android.enroll.EnrollException.Transport)
        }
    }
}
