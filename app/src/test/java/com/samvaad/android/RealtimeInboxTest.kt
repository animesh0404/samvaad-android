package com.samvaad.android

import com.samvaad.android.enroll.MailboxItem
import com.samvaad.android.session.RealtimeInbox
import java.io.IOException
import java.net.URI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 13 realtime-client tests with a scripted fake socket: no TCP,
 * no TLS, no server. The state machine, reconnect bounds, single-
 * refresh rule, revocation handling, and lifecycle are proven here;
 * the real socket factory is proven separately by
 * RealtimeTlsInstrumentedTest.
 *
 * Robolectric (not plain JVM): the MESSAGE path parses through
 * org.json, which is an Android-framework stub on a bare JVM.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class RealtimeInboxTest {

    private companion object {
        const val SERVER = "https://192.168.29.41:8080"
        const val DEVICE_ID = "dev-1"
        const val DESTINATION = "/topic/devices/dev-1"
        const val CONNECTED = "CONNECTED\nversion:1.2\nheart-beat:0,0\n\n\u0000"
        const val BODY =
            "{\"messageId\":\"m-1\",\"conversationId\":\"c-1\",\"sequenceNumber\":7," +
                "\"senderUserId\":\"u-9\",\"senderDeviceId\":\"s-9\"," +
                "\"envelopeType\":\"RATCHET\",\"ciphertext\":\"QUJD\"," +
                "\"serverTimestamp\":\"2026-10-04T00:00:00\"}"
    }

    private class FakeSocket : RealtimeInbox.RealtimeSocket {
        val sent = mutableListOf<String>()
        var closed = 0
        var connectCalls = 0
        var failConnect = false

        override fun connect() {
            connectCalls++
            if (failConnect) throw IOException("link down")
        }

        override fun send(text: String) {
            sent.add(text)
        }

        override fun close() {
            closed++
        }
    }

    private class Harness(
        val maxAttempts: Int = 6,
    ) {
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val created = mutableListOf<Pair<URI, FakeSocket>>()
        val listeners = mutableListOf<RealtimeInbox.SocketEvents>()
        val items = mutableListOf<MailboxItem>()
        var refreshCalls = 0
        var refreshResult: AuthSession? = null
        var failAllConnects = false
        val stops = mutableListOf<RealtimeInbox.StopReason>()
        val client = RealtimeInbox(
            socketFactory = { uri, events ->
                FakeSocket().also {
                    it.failConnect = failAllConnects
                    created.add(uri to it)
                    listeners.add(events)
                }
            },
            parentScope = scope,
            maxReconnectAttempts = maxAttempts,
            baseDelayMillis = 20L,
            maxDelayMillis = 100L,
            jitterBoundMillis = 0L,
            jitter = { 0L },
        )
        val callbacks = object : RealtimeInbox.Callbacks {
            override suspend fun onItem(item: MailboxItem) {
                items.add(item)
            }

            override suspend fun refreshSession(): AuthSession? {
                refreshCalls++
                return refreshResult
            }

            override fun onStopped(reason: RealtimeInbox.StopReason) {
                stops.add(reason)
            }
        }

        fun session(token: String = "access-1") = AuthSession(
            identifier = "alice",
            accessToken = token,
            refreshToken = "refresh-1",
            sessionId = "11111111-2222-3333-4444-555555555555",
        )

        fun start(token: String = "access-1") {
            client.start(session(token), SERVER, DEVICE_ID, callbacks)
        }

        fun socket(index: Int = 0) = created[index].second
        fun events(index: Int = 0) = listeners[index]

        fun await(timeoutMs: Long = 3_000L, condition: () -> Boolean) {
            val end = System.currentTimeMillis() + timeoutMs
            while (!condition()) {
                if (System.currentTimeMillis() > end) {
                    throw AssertionError("condition unmet within ${timeoutMs}ms")
                }
                Thread.sleep(10)
            }
        }

        fun close() {
            client.stop()
            scope.cancel()
        }
    }

    private var harness: Harness? = null

    @After
    fun tearDown() {
        harness?.close()
        harness = null
    }

    private fun messageFrame(
        destination: String = DESTINATION,
        body: String = BODY,
    ) = "MESSAGE\nsubscription:sub-0\ndestination:$destination\n\n$body\u0000"

    // ---- construction guards ----

    @Test
    fun start_rejectsHttpAddress() {
        harness = Harness()
        try {
            harness!!.client.start(
                harness!!.session(), "http://192.168.29.41:8080", DEVICE_ID, harness!!.callbacks,
            )
            throw AssertionError("expected rejection")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("HTTPS"))
        }
        assertTrue(harness!!.created.isEmpty())
    }

    @Test
    fun start_rejectsBlankDevice() {
        harness = Harness()
        try {
            harness!!.client.start(harness!!.session(), SERVER, "  ", harness!!.callbacks)
            throw AssertionError("expected rejection")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("device"))
        }
        assertTrue(harness!!.created.isEmpty())
    }

    @Test
    fun start_isIdempotentWhileRunning() {
        harness = Harness().also { it.start() }
        harness!!.start()
        assertEquals(1, harness!!.created.size)
    }

    // ---- connect/subscribe flow ----

    @Test
    fun open_sendsConnectWithBearerAndNoHeartbeat() {
        harness = Harness().also { it.start() }
        val (uri, socket) = harness!!.created.single()
        assertEquals("wss://192.168.29.41:8080/ws", uri.toString())
        harness!!.events().onOpen()
        val connect = socket.sent.single()
        assertTrue(connect.startsWith("CONNECT\n"))
        assertTrue(connect.contains("\nAuthorization:Bearer access-1\n"))
        assertTrue(connect.contains("\nheart-beat:0,0\n"))
    }

    @Test
    fun connected_subscribesExactOwnDestination() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        val subscribe = harness!!.socket().sent[1]
        assertTrue(subscribe.startsWith("SUBSCRIBE\n"))
        assertTrue(subscribe.contains("\ndestination:$DESTINATION\n"))
        assertTrue(harness!!.client.isRunning)
    }

    @Test
    fun messageForOtherDestination_isIgnored() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        harness!!.events().onText(messageFrame(destination = "/topic/devices/other"))
        assertTrue(harness!!.items.isEmpty())
        assertTrue(harness!!.client.isRunning)
    }

    @Test
    fun message_ingestsParsedItem() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        harness!!.events().onText(messageFrame())
        assertEquals(1, harness!!.items.size)
        val item = harness!!.items.single()
        assertEquals("m-1", item.messageId)
        assertEquals("c-1", item.conversationId)
        assertEquals(7L, item.sequenceNumber)
        assertEquals("s-9", item.senderDeviceId)
        assertEquals("RATCHET", item.envelopeType)
        assertEquals("QUJD", item.ciphertextBase64)
    }

    @Test
    fun malformedMessageBody_isIgnoredWithoutTeardown() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        harness!!.events().onText(messageFrame(body = "not-json"))
        harness!!.events().onText("garbage-without-terminator")
        harness!!.events().onText("")
        assertTrue(harness!!.items.isEmpty())
        assertTrue(harness!!.client.isRunning)
        assertEquals(0, harness!!.socket().closed)
    }

    @Test
    fun neverEmitsSend() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        harness!!.events().onText(messageFrame())
        harness!!.client.stop()
        val sends = harness!!.socket().sent.filter { it.startsWith("SEND") }
        assertTrue(sends.isEmpty())
    }

    // ---- auth failure: single refresh, no loop ----

    @Test
    fun errorBeforeSubscribe_refreshesOnceAndReconnectsWithFreshToken() {
        val h = Harness().also {
            it.refreshResult = it.session("access-2")
            it.start()
        }
        harness = h
        h.events().onOpen()
        h.events().onText("ERROR\nmessage:Forbidden\n\nno\u0000")
        h.await { h.created.size == 2 }
        assertEquals(1, h.refreshCalls)
        // The replacement socket authenticates with the refreshed token.
        h.events(1).onOpen()
        val connect = h.socket(1).sent.single()
        assertTrue(connect.contains("\nAuthorization:Bearer access-2\n"))
        h.events(1).onText(CONNECTED)
        assertTrue(h.client.isRunning)
        assertTrue(h.stops.isEmpty())
    }

    @Test
    fun errorBeforeSubscribe_refreshUnavailable_stops() {
        harness = Harness().also {
            it.refreshResult = null
            it.start()
        }
        harness!!.events().onOpen()
        harness!!.events().onText("ERROR\nmessage:Forbidden\n\nno\u0000")
        harness!!.await { harness!!.stops.isNotEmpty() }
        assertEquals(listOf(RealtimeInbox.StopReason.AuthExhausted), harness!!.stops)
        assertEquals(1, harness!!.created.size)
    }

    @Test
    fun secondAuthFailure_doesNotLoop() {
        val h = Harness().also {
            it.refreshResult = it.session("access-2")
            it.start()
        }
        harness = h
        h.events().onOpen()
        h.events().onText("ERROR\nmessage:Forbidden\n\nno\u0000")
        h.await { h.created.size == 2 }
        h.events(1).onOpen()
        h.events(1).onText("ERROR\nmessage:Forbidden\n\nno\u0000")
        h.await { h.stops.isNotEmpty() }
        assertEquals(listOf(RealtimeInbox.StopReason.AuthExhausted), h.stops)
        assertEquals(1, h.refreshCalls)
        assertEquals(2, h.created.size)
    }

    // ---- revocation: revalidate, never reconnect ----

    @Test
    fun errorAfterSubscribe_reportsRevokedWithoutRefresh() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        harness!!.events().onText("ERROR\nmessage:Forbidden\n\nno\u0000")
        harness!!.await { harness!!.stops.isNotEmpty() }
        assertEquals(listOf(RealtimeInbox.StopReason.Revoked), harness!!.stops)
        assertEquals(0, harness!!.refreshCalls)
        assertEquals(1, harness!!.created.size)
        assertFalse(harness!!.client.isRunning)
    }

    @Test
    fun policyViolationClose_reportsRevokedWithoutReconnect() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        harness!!.events().onClosed(1008, true)
        harness!!.await { harness!!.stops.isNotEmpty() }
        assertEquals(listOf(RealtimeInbox.StopReason.Revoked), harness!!.stops)
        Thread.sleep(150)
        assertEquals(1, harness!!.created.size)
    }

    // ---- transport loss: bounded reconnect, cancellable ----

    @Test
    fun transportLoss_reconnectsWithinBoundsThenStops() {
        val h = Harness(maxAttempts = 2).also { it.start() }
        harness = h
        h.events().onOpen()
        h.events().onClosed(1006, true)
        h.await { h.created.size == 2 }
        h.events(1).onClosed(1006, true)
        h.await { h.created.size == 3 }
        h.events(2).onClosed(1006, true)
        h.await { h.stops.isNotEmpty() }
        assertEquals(listOf(RealtimeInbox.StopReason.AttemptsExhausted), h.stops)
        // Initial socket + exactly two bounded retries.
        assertEquals(3, h.created.size)
    }

    @Test
    fun stop_cancelsPendingReconnect() {
        val h = Harness(maxAttempts = 5).also { it.start() }
        harness = h
        h.events().onOpen()
        h.events().onClosed(1006, true)
        h.client.stop()
        Thread.sleep(300)
        assertEquals(1, h.created.size)
        assertTrue(h.stops.isEmpty())
        assertFalse(h.client.isRunning)
    }

    @Test
    fun stop_sendsDisconnectAndCloses() {
        harness = Harness().also { it.start() }
        harness!!.events().onOpen()
        harness!!.events().onText(CONNECTED)
        harness!!.client.stop()
        val socket = harness!!.socket()
        assertTrue(socket.sent.any { it.startsWith("DISCONNECT\n") })
        assertTrue(socket.closed >= 1)
        assertFalse(harness!!.client.isRunning)
    }

    @Test
    fun syncConnectFailure_countsAgainstRetryBudget() {
        val h = Harness(maxAttempts = 1).also { it.failAllConnects = true }
        harness = h
        h.start()
        // Initial connect throws synchronously, then the single retry.
        h.await { h.created.size == 2 }
        h.await { h.stops.isNotEmpty() }
        assertEquals(listOf(RealtimeInbox.StopReason.AttemptsExhausted), h.stops)
        assertEquals(2, h.created.size)
    }
}
