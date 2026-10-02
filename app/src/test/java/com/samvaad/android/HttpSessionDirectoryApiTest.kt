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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Transport contract for device discovery at the real
 * [HttpE2eeDeviceApi] boundary, against a minimal loopback socket stub
 * (mirrors [HttpE2eeDeviceApiTest]): exact paths/methods, bearer auth,
 * `requestId` body, response parsing, Base64 opacity, status taxonomy,
 * and failure classification. No live server, no crypto.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpSessionDirectoryApiTest {

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
        }, "stub-session-server").apply { isDaemon = true }

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

    private fun recipientJson(
        deviceId: String = "22222222-2222-3333-4444-555555555555",
        signalDeviceId: Int = 2,
        kyber: Boolean = true,
        hasOtk: Boolean = true,
    ): JSONObject {
        val json = JSONObject()
            .put("deviceId", deviceId)
            .put("registrationId", 7001)
            .put("signalDeviceId", signalDeviceId)
            .put("deviceIdentityPublicKey", "aWRlbnRpdHk=")
            .put("signedPrekeyId", 11)
            .put("signedPrekey", "c2lnbmVk")
            .put("signedPrekeySignature", "c2ln")
            .put("hasAvailableOneTimePrekey", hasOtk)
            .put("deviceRole", "COMPANION")
        if (kyber) {
            json.put("kyberPrekeyId", 21)
                .put("kyberPrekey", "a3liZXI=")
                .put("kyberPrekeySignature", "a3NpZw==")
        } else {
            json.put("kyberPrekeyId", JSONObject.NULL)
                .put("kyberPrekey", JSONObject.NULL)
                .put("kyberPrekeySignature", JSONObject.NULL)
        }
        return json
    }

    private fun claimJson(withOtk: Boolean = true, kyber: Boolean = true): String {
        val json = recipientJson(kyber = kyber)
        if (withOtk) {
            json.put("oneTimePrekey", JSONObject()
                .put("prekeyId", 101)
                .put("publicKey", "b3Rway0="))
        } else {
            json.put("oneTimePrekey", JSONObject.NULL)
        }
        return json.toString()
    }

    @Test
    fun directory_getsExactPath_withBearerAuth() {
        val port = serve(200 to JSONArray(listOf(recipientJson())).toString())
        val devices = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .listRecipientDevices(session, "http://localhost:$port", "bob")
        }
        assertEquals(1, devices.size)
        val d = devices.single()
        assertEquals("22222222-2222-3333-4444-555555555555", d.deviceId)
        assertEquals(7001, d.registrationId)
        assertEquals(2, d.signalDeviceId)
        assertEquals("aWRlbnRpdHk=", d.deviceIdentityPublicKey)
        assertEquals(11, d.signedPrekeyId)
        assertTrue(d.hasAvailableOneTimePrekey)
        assertEquals("COMPANION", d.deviceRole)
        assertEquals(21, d.kyberPrekeyId)
        // Standard Base64 opacity preserved end to end.
        java.util.Base64.getDecoder().decode(d.deviceIdentityPublicKey)

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("GET /api/e2ee/users/bob/devices "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
    }

    @Test
    fun directory_encodesUsernameInPath() {
        val port = serve(200 to "[]")
        runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .listRecipientDevices(session, "http://localhost:$port", "bob smith+tag")
        }
        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("GET /api/e2ee/users/bob+smith%2Btag/devices "))
    }

    @Test
    fun directory_emptyArray_parsesToEmptyList() {
        val port = serve(200 to "[]")
        val devices = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .listRecipientDevices(session, "http://localhost:$port", "bob")
        }
        assertTrue(devices.isEmpty())
    }

    @Test
    fun directory_multipleDevices_nullKyberPreserved() {
        val port = serve(200 to JSONArray(listOf(
            recipientJson(deviceId = "d-1", signalDeviceId = 1),
            recipientJson(deviceId = "d-2", signalDeviceId = 2, kyber = false, hasOtk = false),
        )).toString())
        val devices = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .listRecipientDevices(session, "http://localhost:$port", "bob")
        }
        assertEquals(2, devices.size)
        assertEquals("d-1", devices[0].deviceId)
        assertEquals("d-2", devices[1].deviceId)
        assertNull(devices[1].kyberPrekeyId)
        assertNull(devices[1].kyberPrekey)
        assertNull(devices[1].kyberPrekeySignature)
        assertFalse(devices[1].hasAvailableOneTimePrekey)
    }

    @Test
    fun directory_401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .listRecipientDevices(session, "http://localhost:$port", "bob")
            }
        }
    }

    @Test
    fun directory_403_mapsToForbidden() {
        val port = serve(403 to JSONObject().put("reason", "OTHER").toString())
        assertThrows(EnrollException.Forbidden::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .listRecipientDevices(session, "http://localhost:$port", "bob")
            }
        }
    }

    @Test
    fun directory_403_recoveryReason_preserved() {
        val port = serve(403 to JSONObject().put("reason", "E2EE_RECOVERY_REQUIRED").toString())
        assertThrows(EnrollException.RecoveryRequired::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .listRecipientDevices(session, "http://localhost:$port", "bob")
            }
        }
    }

    @Test
    fun directory_404_mapsToNotFound() {
        val port = serve(404 to "{}")
        assertThrows(EnrollException.NotFound::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .listRecipientDevices(session, "http://localhost:$port", "ghost")
            }
        }
    }

    @Test
    fun directory_malformedJson_mapsToMalformed() {
        val port = serve(200 to "{not json")
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .listRecipientDevices(session, "http://localhost:$port", "bob")
            }
        }
    }

    @Test
    fun directory_httpScheme_rejectedLocally() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi().listRecipientDevices(session, "http://localhost:1", "bob")
            }
        }
    }

    @Test
    fun claim_postsRequestId_parsesBundleWithOtk() {
        val port = serve(200 to claimJson(withOtk = true))
        val requestId = UUID.randomUUID()
        val bundle = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .claimOneTimePrekey(session, "http://localhost:$port", "dev-9", requestId)
        }
        assertEquals("22222222-2222-3333-4444-555555555555", bundle.deviceId)
        assertEquals(101, bundle.oneTimePrekey!!.prekeyId)
        assertEquals("b3Rway0=", bundle.oneTimePrekey.publicKey)
        assertEquals(21, bundle.kyberPrekeyId)

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/devices/dev-9/one-time-prekeys/claim "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        // Fresh UUID per attempt, canonical string form.
        assertEquals(requestId.toString(), sent.getString("requestId"))
        UUID.fromString(sent.getString("requestId"))
    }

    @Test
    fun claim_fallback_nullOtk_parses() {
        val port = serve(200 to claimJson(withOtk = false))
        val bundle = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false)
                .claimOneTimePrekey(session, "http://localhost:$port", "dev-9", UUID.randomUUID())
        }
        assertNull(bundle.oneTimePrekey)
        // Kyber rides along even on fallback.
        assertEquals(21, bundle.kyberPrekeyId)
    }

    @Test
    fun claim_404_mapsToNotFound() {
        val port = serve(404 to "{}")
        assertThrows(EnrollException.NotFound::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .claimOneTimePrekey(session, "http://localhost:$port", "gone", UUID.randomUUID())
            }
        }
    }

    @Test
    fun claim_403_mapsToForbidden() {
        val port = serve(403 to "{}")
        assertThrows(EnrollException.Forbidden::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .claimOneTimePrekey(session, "http://localhost:$port", "dev-9", UUID.randomUUID())
            }
        }
    }

    @Test
    fun claim_409_mapsToConflict() {
        val port = serve(409 to "{}")
        assertThrows(EnrollException.Conflict::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .claimOneTimePrekey(session, "http://localhost:$port", "dev-9", UUID.randomUUID())
            }
        }
    }

    @Test
    fun claim_401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .claimOneTimePrekey(session, "http://localhost:$port", "dev-9", UUID.randomUUID())
            }
        }
    }

    @Test
    fun claim_malformedJson_mapsToMalformed() {
        val port = serve(200 to "[1,2")
        assertThrows(EnrollException.Malformed::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false)
                    .claimOneTimePrekey(session, "http://localhost:$port", "dev-9", UUID.randomUUID())
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
                HttpE2eeDeviceApi(requireHttps = false)
                    .claimOneTimePrekey(session, "http://localhost:$port", "dev-9", UUID.randomUUID())
            }
        }
    }
}
