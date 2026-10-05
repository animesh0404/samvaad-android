package com.samvaad.android

import com.samvaad.android.friends.FriendException
import com.samvaad.android.friends.HttpFriendsApi
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
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
 * Transport contract for the Slice 14 friends boundary at the real
 * [HttpFriendsApi], against a minimal loopback socket stub (mirrors
 * [HttpInboxApiTest]): exact paths/query/body, Bearer auth, response
 * parsing, status taxonomy, and failure classification. No live
 * server.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpFriendsApiTest {

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
        }, "stub-friends-server").apply { isDaemon = true }

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

    private fun requestJson(
        requestId: String = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        status: String = "PENDING",
    ): JSONObject = JSONObject()
        .put("requestId", requestId)
        .put("senderUserId", "11111111-1111-1111-1111-111111111111")
        .put("senderUsername", "alice")
        .put("recipientUserId", "22222222-2222-2222-2222-222222222222")
        .put("recipientUsername", "bob")
        .put("status", status)
        .put("createdAt", "2026-10-05T10:00:00")
        .put("respondedAt", JSONObject.NULL)

    @Test
    fun send_postsExactPath_withBearerAuth_andParses() {
        val port = serve(201 to requestJson().toString())
        val record = runBlocking {
            HttpFriendsApi(requireHttps = false).sendRequest(session, "http://localhost:$port", "bob")
        }
        assertEquals("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", record.requestId)
        assertEquals("alice", record.senderUsername)
        assertEquals("bob", record.recipientUsername)
        assertEquals("PENDING", record.status)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/friend-requests "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        assertTrue(raw.contains("\"username\":\"bob\""))
    }

    @Test
    fun send_unknownUser_isNotFound() {
        val port = serve(404 to """{"reason":"USER_NOT_FOUND"}""")
        assertThrows(FriendException.NotFound::class.java) {
            runBlocking {
                HttpFriendsApi(requireHttps = false)
                    .sendRequest(session, "http://localhost:$port", "ghost")
            }
        }
    }

    @Test
    fun send_selfRequest_isForbidden() {
        val port = serve(403 to """{"reason":"FORBIDDEN"}""")
        assertThrows(FriendException.Forbidden::class.java) {
            runBlocking {
                HttpFriendsApi(requireHttps = false)
                    .sendRequest(session, "http://localhost:$port", "alice")
            }
        }
    }

    @Test
    fun send_duplicate_isConflict() {
        val port = serve(409 to """{"reason":"CONFLICT"}""")
        assertThrows(FriendException.Conflict::class.java) {
            runBlocking {
                HttpFriendsApi(requireHttps = false)
                    .sendRequest(session, "http://localhost:$port", "bob")
            }
        }
    }

    @Test
    fun incoming_getsExactPath_andParses() {
        val port = serve(200 to JSONArray(listOf(requestJson())).toString())
        val records = runBlocking {
            HttpFriendsApi(requireHttps = false).listIncoming(session, "http://localhost:$port")
        }
        assertEquals(1, records.size)
        assertEquals("alice", records.single().senderUsername)
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("GET /api/friend-requests/incoming "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
    }

    @Test
    fun incoming_empty_isEmptyList() {
        val port = serve(200 to "[]")
        val records = runBlocking {
            HttpFriendsApi(requireHttps = false).listIncoming(session, "http://localhost:$port")
        }
        assertTrue(records.isEmpty())
    }

    @Test
    fun outgoing_getsExactPath() {
        val port = serve(200 to "[]")
        runBlocking {
            HttpFriendsApi(requireHttps = false).listOutgoing(session, "http://localhost:$port")
        }
        assertTrue(server!!.requests.single().startsWith("GET /api/friend-requests/outgoing "))
    }

    @Test
    fun accept_postsExactPath_andParsesAccepted() {
        val port = serve(200 to requestJson(status = "ACCEPTED").toString())
        val record = runBlocking {
            HttpFriendsApi(requireHttps = false).acceptRequest(
                session,
                "http://localhost:$port",
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            )
        }
        assertEquals("ACCEPTED", record.status)
        val raw = server!!.requests.single()
        assertTrue(
            raw.startsWith(
                "POST /api/friend-requests/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/accept "
            )
        )
    }

    @Test
    fun accept_goneRequest_isConflict() {
        val port = serve(409 to """{"reason":"CONFLICT"}""")
        assertThrows(FriendException.Conflict::class.java) {
            runBlocking {
                HttpFriendsApi(requireHttps = false).acceptRequest(
                    session, "http://localhost:$port", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
                )
            }
        }
    }

    @Test
    fun reject_postsExactPath() {
        val port = serve(200 to requestJson(status = "REJECTED").toString())
        val record = runBlocking {
            HttpFriendsApi(requireHttps = false).rejectRequest(
                session,
                "http://localhost:$port",
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            )
        }
        assertEquals("REJECTED", record.status)
        assertTrue(
            server!!.requests.single().startsWith(
                "POST /api/friend-requests/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/reject "
            )
        )
    }

    @Test
    fun cancel_postsExactPath() {
        val port = serve(200 to requestJson(status = "CANCELLED").toString())
        val record = runBlocking {
            HttpFriendsApi(requireHttps = false).cancelRequest(
                session,
                "http://localhost:$port",
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            )
        }
        assertEquals("CANCELLED", record.status)
        assertTrue(
            server!!.requests.single().startsWith(
                "POST /api/friend-requests/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/cancel "
            )
        )
    }

    @Test
    fun friends_getsExactPath_andParses() {
        val body = JSONArray(
            listOf(
                JSONObject()
                    .put("userId", "22222222-2222-2222-2222-222222222222")
                    .put("username", "bob")
            )
        ).toString()
        val port = serve(200 to body)
        val friends = runBlocking {
            HttpFriendsApi(requireHttps = false).listFriends(session, "http://localhost:$port")
        }
        assertEquals(1, friends.size)
        assertEquals("bob", friends.single().username)
        assertEquals("22222222-2222-2222-2222-222222222222", friends.single().userId)
        assertTrue(server!!.requests.single().startsWith("GET /api/friends "))
    }

    @Test
    fun lookup_getsExactPath_withEncoding_andParses() {
        val body = JSONObject()
            .put("userId", "22222222-2222-2222-2222-222222222222")
            .put("username", "bob")
            .toString()
        val port = serve(200 to body)
        val entry = runBlocking {
            HttpFriendsApi(requireHttps = false).lookupUser(session, "http://localhost:$port", "bob")
        }
        assertEquals("bob", entry.username)
        assertTrue(
            server!!.requests.single().startsWith("GET /api/users/lookup?username=bob ")
        )
    }

    @Test
    fun lookup_unknownUser_isNotFound() {
        val port = serve(404 to """{"reason":"USER_NOT_FOUND"}""")
        assertThrows(FriendException.NotFound::class.java) {
            runBlocking {
                HttpFriendsApi(requireHttps = false)
                    .lookupUser(session, "http://localhost:$port", "ghost")
            }
        }
    }

    @Test
    fun unauthorized_isUnauthorized() {
        val port = serve(401 to """{"reason":"UNAUTHORIZED"}""")
        assertThrows(FriendException.Unauthorized::class.java) {
            runBlocking {
                HttpFriendsApi(requireHttps = false).listFriends(session, "http://localhost:$port")
            }
        }
    }

    @Test
    fun malformedBody_isTransport() {
        val port = serve(200 to "not-json{{")
        assertThrows(FriendException.Transport::class.java) {
            runBlocking {
                HttpFriendsApi(requireHttps = false).listFriends(session, "http://localhost:$port")
            }
        }
    }

    @Test
    fun https_isEnforcedByDefault() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpFriendsApi().listFriends(session, "http://localhost:1")
            }
        }
    }
}
