package com.samvaad.android

import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.HttpE2eeDeviceApi
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 10 transport contracts at the real [HttpE2eeDeviceApi] boundary,
 * against a minimal loopback socket stub (mirrors [HttpE2eeDeviceApiTest]):
 * exact paths/bodies for approve, bind, and recovery-enroll; 200-vs-201
 * semantics; 404/409 taxonomy; reason-token handling; HTTPS-only; and the
 * no-recovery-code-leakage invariant. No live server.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HttpDeviceActionApiTest {

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
        }, "stub-device-action-server").apply { isDaemon = true }

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

    private fun deviceBody(
        deviceId: String = "22222222-2222-3333-4444-555555555555",
        status: String = "ACTIVE",
        role: String = "COMPANION",
        signalId: Int = 2,
        available: Long = 0,
        identityB64: String = "aWRlbnRpdHk=",
        withKyberId: Boolean = true,
    ): String {
        val json = JSONObject()
            .put("deviceId", deviceId)
            .put("registrationId", 4242)
            .put("signalDeviceId", signalId)
            .put("deviceIdentityPublicKey", identityB64)
            .put("signedPrekeyId", 1)
            .put("deviceRole", role)
            .put("status", status)
            .put("availablePrekeys", available)
        if (withKyberId) json.put("kyberPrekeyId", 7)
        return json.toString()
    }

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

    // ---- approve ----

    @Test
    fun approve_postsToExactPath_withBearerAuth() {
        val port = serve(200 to deviceBody(status = "ACTIVE"))
        val device = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                session, "http://localhost:$port", "target-device-id"
            )
        }
        assertEquals("22222222-2222-3333-4444-555555555555", device.deviceId)
        assertEquals("ACTIVE", device.status)
        assertEquals("COMPANION", device.deviceRole)
        assertEquals(2, device.signalDeviceId)
        assertEquals(7, device.kyberPrekeyId)

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/devices/target-device-id/approve "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
    }

    @Test
    fun approve_sendsExactlyEmptyJsonBody() {
        // The server contract takes no request body
        // (E2eeDeviceController.approveDevice has no @RequestBody, so the
        // entity body is ignored). The client sends exactly `{}` through
        // the shared POST helper rather than inventing fields.
        val port = serve(200 to deviceBody(status = "ACTIVE"))
        runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                session, "http://localhost:$port", "target-device-id"
            )
        }

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/devices/target-device-id/approve "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        assertEquals(0, sent.length())
    }

    @Test
    fun approve_200_pendingRow_parsesWithoutPromotion() {
        val port = serve(200 to deviceBody(status = "PENDING"))
        val device = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                session, "http://localhost:$port", "d1"
            )
        }
        // The client reports server truth; promotion to Active happens only
        // after the coordinator re-lists and reads ACTIVE.
        assertEquals("PENDING", device.status)
    }

    @Test
    fun approve_403_plain_mapsToServerRejected() {
        val port = serve(403 to JSONObject().put("message", "denied").toString())
        assertThrows(EnrollException.ServerRejected::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                    session, "http://localhost:$port", "d1"
                )
            }
        }
    }

    @Test
    fun approve_404_mapsToNotFound() {
        val port = serve(404 to "{}")
        assertThrows(EnrollException.NotFound::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                    session, "http://localhost:$port", "unknown"
                )
            }
        }
    }

    @Test
    fun approve_409_mapsToConflict() {
        val port = serve(409 to "{}")
        assertThrows(EnrollException.Conflict::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                    session, "http://localhost:$port", "revoked"
                )
            }
        }
    }

    @Test
    fun approve_401_mapsToUnauthorized() {
        val port = serve(401 to "{}")
        assertThrows(EnrollException.Unauthorized::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                    session, "http://localhost:$port", "d1"
                )
            }
        }
    }

    // ---- bind ----

    @Test
    fun bind_postsExactBody_withBearerAuth() {
        val port = serve(200 to deviceBody())
        val device = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).bindDevice(
                session, "http://localhost:$port", "existing-id", "SENTINEL-CODE-1"
            )
        }
        assertEquals("22222222-2222-3333-4444-555555555555", device.deviceId)
        assertEquals("ACTIVE", device.status)

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/devices/existing-id/bind "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        // Exactly the contracted field — no key material, no invented keys.
        assertEquals(1, sent.length())
        assertEquals("SENTINEL-CODE-1", sent.getString("recoveryCode"))
    }

    @Test
    fun bind_blankCode_rejectedLocallyWithoutWire() {
        val port = serve(200 to deviceBody())
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).bindDevice(
                    session, "http://localhost:$port", "existing-id", "   "
                )
            }
        }
        assertTrue(server!!.requests.isEmpty())
    }

    @Test
    fun bind_403_wrongCode_mapsToServerRejected_withoutLeak() {
        val code = "SENTINEL-CODE-7749"
        val port = serve(403 to JSONObject().put("message", "bad code").toString())
        try {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).bindDevice(
                    session, "http://localhost:$port", "existing-id", code
                )
            }
            throw AssertionError("expected ServerRejected")
        } catch (e: EnrollException.ServerRejected) {
            assertFalse(e.message.orEmpty().contains(code))
        }
    }

    @Test
    fun bind_409_mapsToConflict() {
        val port = serve(409 to "{}")
        assertThrows(EnrollException.Conflict::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).bindDevice(
                    session, "http://localhost:$port", "existing-id", "code-9"
                )
            }
        }
    }

    // ---- recovery-enroll ----

    @Test
    fun recoverEnroll_postsExactBody_andRequires201() {
        val port = serve(201 to deviceBody(role = "PRIMARY", signalId = 1))
        val device = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).recoverEnroll(
                session, "http://localhost:$port", "SENTINEL-CODE-2", enrollRequest()
            )
        }
        assertEquals("PRIMARY", device.deviceRole)
        assertEquals(1, device.signalDeviceId)

        val raw = server!!.requests.single()
        assertTrue(raw.startsWith("POST /api/e2ee/recovery/enroll "))
        assertTrue(raw.contains("Authorization: Bearer access-test-token"))
        val sent = JSONObject(raw.substringAfterLast("\n"))
        assertEquals("SENTINEL-CODE-2", sent.getString("recoveryCode"))
        val inner = sent.getJSONObject("device")
        assertEquals(4242, inner.getInt("registrationId"))
        assertEquals("aWRlbnRpdHk=", inner.getString("deviceIdentityPublicKey"))
        assertEquals(1, inner.getInt("signedPrekeyId"))
        assertEquals("c2lnbmVk", inner.getString("signedPrekey"))
        assertEquals("c2ln", inner.getString("signedPrekeySignature"))
        assertEquals(1, inner.getInt("kyberPrekeyId"))
        assertEquals("a3liZXI=", inner.getString("kyberPrekey"))
        assertEquals("a3NpZw==", inner.getString("kyberPrekeySignature"))
        assertEquals("ANDROID", inner.getString("clientPlatform"))
    }

    @Test
    fun recoverEnroll_200_isNotAccepted() {
        // Recovery-enroll creates; only 201 counts. A 200 would be a
        // contract violation, surfaced rather than trusted.
        val port = serve(200 to deviceBody())
        assertThrows(EnrollException.ServerRejected::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).recoverEnroll(
                    session, "http://localhost:$port", "code-1", enrollRequest()
                )
            }
        }
    }

    @Test
    fun recoverEnroll_403_withReason_mapsToRecoveryRequired() {
        val port = serve(
            403 to JSONObject()
                .put("message", "no")
                .put("reason", "E2EE_RECOVERY_REQUIRED")
                .toString()
        )
        assertThrows(EnrollException.RecoveryRequired::class.java) {
            runBlocking {
                HttpE2eeDeviceApi(requireHttps = false).recoverEnroll(
                    session, "http://localhost:$port", "code-1", enrollRequest()
                )
            }
        }
    }

    @Test
    fun deviceDto_withoutKyber_parsesNull() {
        val port = serve(200 to deviceBody(withKyberId = false))
        val device = runBlocking {
            HttpE2eeDeviceApi(requireHttps = false).approveDevice(
                session, "http://localhost:$port", "d1"
            )
        }
        assertNull(device.kyberPrekeyId)
    }

    @Test
    fun deviceActions_httpScheme_rejectedLocally() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi().approveDevice(session, "http://localhost:1", "d1")
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi().bindDevice(session, "http://localhost:1", "d1", "code")
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                HttpE2eeDeviceApi().recoverEnroll(
                    session, "http://localhost:1", "code", enrollRequest()
                )
            }
        }
    }
}
