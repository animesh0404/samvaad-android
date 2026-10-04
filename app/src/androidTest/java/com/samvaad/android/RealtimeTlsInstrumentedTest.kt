package com.samvaad.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.net.URI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.java_websocket.client.WebSocketClient
import org.java_websocket.handshake.ServerHandshake
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Slice 13 dependency/TLS gate: proves the Java-WebSocket default TLS
 * path respects the debug Network Security Config trust anchor with no
 * custom TrustManager, HostnameVerifier, or socket factory.
 *
 * The client below sets NO factory, so it uses
 * `SSLSocketFactory.getDefault()` — the platform default that enforces
 * Network Security Config on API 24+ (minSdk 30). A successful `wss://`
 * handshake against the LAN dev server proves the anchor applies to this
 * library untouched. No STOMP frames are exchanged; the socket is closed
 * immediately (the server holds no authenticated state for it).
 */
@RunWith(AndroidJUnit4::class)
class RealtimeTlsInstrumentedTest {

    private companion object {
        const val LAN_WSS_URL = "wss://192.168.29.41:8080/ws"
    }

    @Test
    fun defaultFactory_wssHandshake_succeedsWithDebugTrustAnchor() {
        val opened = CountDownLatch(1)
        val client = object : WebSocketClient(URI(LAN_WSS_URL)) {
            override fun onOpen(handshakedata: ServerHandshake?) {
                opened.countDown()
            }

            override fun onMessage(message: String?) = Unit
            override fun onClose(code: Int, reason: String?, remote: Boolean) = Unit
            override fun onError(ex: Exception?) = Unit
        }
        try {
            assertTrue(
                "wss handshake failed: default TLS path does not trust the LAN dev server",
                client.connectBlocking(15, TimeUnit.SECONDS),
            )
            assertTrue(opened.await(5, TimeUnit.SECONDS))
        } finally {
            try {
                client.closeBlocking()
            } catch (_: Exception) {
                // Best-effort teardown for a proof socket.
            }
        }
    }
}
