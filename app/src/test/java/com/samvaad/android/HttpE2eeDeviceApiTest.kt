package com.samvaad.android

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
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.HttpE2eeDeviceApi
import com.samvaad.android.enroll.OneTimePrekeyUpload

/**
 * Transport contract at the real [HttpE2eeDeviceApi] boundary, against a
 * minimal loopback socket stub (mirrors [AuthApiTest]): exact JSON shapes,
 * HTTPS-only, status taxonomy, and failure classification. No live server.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpE2eeDeviceApiTest {

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
        }, "stub-e2ee-server").apply { isDaemon = true }

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

    private fun enrollRequest() = EnrollRequest(
        registrationId = 4242,
        deviceIdentityPublicKey = "aWRlbnRpdHk=",
        signedPrekeyId = 1,
        signedPrekey = "c2lnbmVk",
        signedPrekeySignature = "c2ln",
        kyberPrekeyId = 1,
        kyberPrekey = "a3liZXI=",
        kyberPrekeySignature = "a3NpZw==",
    )

    private fun enrollSuccessBody(identityB64: String = "aWRlbnRpdHk="): String =
        JSONObject()
            .put("device", JSONObject()
                .put("deviceId", "22222222-2222-3333-4444-555555555555")
                .put("registrationId", 4242)
                .put("signalDeviceId", 1)
                .put("deviceIdentityPublicKey", identityB64)
                .put("signedPrekeyId", 1)
                .put("deviceRole", "PRIMARY")
                .put("status", "ACTIVE")
                .put("availablePrekeys", 0))
            .put("enrollmentState", "NEVER_ENROLLED")
            .put("recoveryCodes", JSONArray(listOf("code-1", "code-2")))
            .toString()

    @Test
    fun enroll_postsExactJsonShape_withBearerAuth() {
        val port = serve(201 to enrollSuccessBody())
        val result = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
        }
        assertEquals("22222222-2222-3333-4444-555555555555", result.device.deviceId)
        assertEquals(1, result.device.signalDeviceId)
        assertEquals("PRIMARY", result.device.deviceRole)
        assertEquals("ACTIVE", result.device.status)
        assertEquals(listOf("code-1", "code-2"), result.recoveryCodes)

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/devices "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        assertEquals(4242, sent.getInt("registrationId"))
        assertEquals("aWRlbnRpdHk=", sent.getString("deviceIdentityPublicKey"))
        assertEquals(1, sent.getInt("signedPrekeyId"))
        assertEquals("c2lnbmVk", sent.getString("signedPrekey"))
        assertEquals("c2ln", sent.getString("signedPrekeySignature"))
        assertEquals(1, sent.getInt("kyberPrekeyId"))
        assertEquals("a3liZXI=", sent.getString("kyberPrekey"))
        assertEquals("a3NpZw==", sent.getString("kyberPrekeySignature"))
        assertEquals("ANDROID", sent.getString("clientPlatform"))
        // Standard Base64 round-trips through the wire shape.
        java.util.Base64.getDecoder().decode(sent.getString("deviceIdentityPublicKey"))
    }

    @Test
    fun upload_postsExactBatchShape() {
        val port = serve(200 to "{}")
        val batch = List(100) { i ->
            OneTimePrekeyUpload(prekeyId = i + 1, publicKey = "b3Rway0$i")
        }
        runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).uploadOneTimePrekeys(
                session, "http://localhost:$port", "dev-1", batch
            )
        }
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("PUT /api/e2ee/devices/dev-1/one-time-prekeys "))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        val prekeys = sent.getJSONArray("prekeys")
        assertEquals(100, prekeys.length())
        assertEquals(1, prekeys.getJSONObject(0).getInt("prekeyId"))
        assertEquals(100, prekeys.getJSONObject(99).getInt("prekeyId"))
    }

    @Test
    fun list_parsesDeviceList() {
        val port = serve(200 to JSONObject()
            .put("enrollmentState", "ENROLLED_ACTIVE")
            .put("devices", JSONArray(listOf(
                JSONObject()
                    .put("deviceId", "d1")
                    .put("registrationId", 7)
                    .put("signalDeviceId", 1)
                    .put("deviceIdentityPublicKey", "a2V5")
                    .put("signedPrekeyId", 3)
                    .put("deviceRole", "PRIMARY")
                    .put("status", "ACTIVE")
                    .put("availablePrekeys", 42)
            )))
            .toString())
        val list = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).listDevices(session, "http://localhost:$port")
        }
        assertEquals("ENROLLED_ACTIVE", list.enrollmentState)
        assertEquals(1, list.devices.size)
        assertEquals(42L, list.devices.single().availablePrekeys)
    }

    @Test
    fun httpScheme_rejectedLocally() {
        // Default production guard: plaintext rejected before any socket opens.
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi().listDevices(session, "http://localhost:1")
            }
        }
    }

    @Test
    fun status400_mapsToBadRequest() {
        val port = serve(400 to "{}")
        assertThrows(EnrollException.BadRequest::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }

    @Test
    fun status401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }

    @Test
    fun status403_withRecoveryReason_mapsToRecoveryRequired() {
        val port = serve(
            403 to JSONObject()
                .put("message", "recovery needed")
                .put("reason", "E2EE_RECOVERY_REQUIRED")
                .toString()
        )
        assertThrows(EnrollException.RecoveryRequired::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }

    @Test
    fun status403_otherReason_mapsToServerRejected() {
        val port = serve(
            403 to JSONObject()
                .put("message", "no")
                .put("reason", "SOMETHING_ELSE")
                .toString()
        )
        assertThrows(EnrollException.ServerRejected::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }

    @Test
    fun status409_mapsToConflict() {
        val port = serve(409 to "{}")
        assertThrows(EnrollException.Conflict::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }

    @Test
    fun status404_mapsToServerRejected() {
        val port = serve(404 to "{}")
        assertThrows(EnrollException.ServerRejected::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }

    @Test
    fun malformed201_mapsToTransport() {
        val port = serve(201 to "{not json")
        assertThrows(EnrollException.Transport::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }

    @Test
    fun connectionRefused_mapsToTransport() {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        assertThrows(EnrollException.Transport::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).enroll(session, "http://localhost:$port", enrollRequest())
            }
        }
    }
}
