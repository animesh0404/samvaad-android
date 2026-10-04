package com.samvaad.android.session

import com.samvaad.android.AuthSession
import com.samvaad.android.enroll.MailboxItem
import com.samvaad.android.enroll.parseMailboxItem
import java.net.URI
import kotlin.math.min
import kotlin.random.Random
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.java_websocket.client.WebSocketClient
import org.java_websocket.handshake.ServerHandshake
import org.json.JSONException
import org.json.JSONObject

/**
 * Foreground-only realtime inbound delivery over the server STOMP
 * device channel (`wss://<host>/ws`, SUBSCRIBE
 * `/topic/devices/{deviceId}`).
 *
 * Delivery-only hint transport: parsed [MailboxItem]s are handed to the
 * owner's ingest path (the same durable InboxProcessor pipeline as
 * mailbox reconciliation). This client persists nothing, ACKs nothing,
 * and never emits STOMP SEND (the server has no client SEND contract).
 *
 * Lifecycle contract:
 * - [start] is idempotent while running; the owner calls it after a
 *   successful [ReconciliationSweep] (sweep-before-subscribe) and stops
 *   calling it when the foreground scope ends.
 * - [stop] is idempotent: best-effort DISCONNECT, socket close, pending
 *   reconnect cancelled. The owner calls it on logout (BEFORE server
 *   revocation) and on leaving the foreground scope.
 * - Transport loss while started schedules a BOUNDED foreground
 *   reconnect (exponential backoff + jitter, capped attempts). Stopping
 *   cancels it: there is no reconnect while backgrounded.
 * - STOMP auth failure triggers AT MOST one session refresh via
 *   [Callbacks.refreshSession] and one reconnect with the fresh token;
 *   anything else stops and reports, never loops.
 * - Server revocation (POLICY_VIOLATION close, post-subscription ERROR)
 *   never reconnects: it stops and reports so the owner revalidates
 *   authoritative device state first.
 *
 * No frame bodies are logged: MESSAGE bodies carry ciphertext.
 */
class RealtimeInbox(
    private val socketFactory: (URI, SocketEvents) -> RealtimeSocket = { uri, events ->
        JavaWebSocketSocket(uri, events)
    },
    parentScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    private val maxReconnectAttempts: Int = 6,
    private val baseDelayMillis: Long = 1_000L,
    private val maxDelayMillis: Long = 30_000L,
    private val jitterBoundMillis: Long = 1_000L,
    private val jitter: (Long) -> Long = { bound -> if (bound > 0) Random.nextLong(bound) else 0L },
) {

    /** Socket abstraction so host tests drive the state machine without TCP. */
    interface RealtimeSocket {
        fun connect()
        fun send(text: String)
        fun close()
    }

    /** Raw transport events from the socket (any thread). */
    interface SocketEvents {
        fun onOpen()
        fun onText(text: String)
        fun onClosed(code: Int, remote: Boolean)
        fun onTransportError()
    }

    /** Terminal stop reasons reported to the owner. */
    enum class StopReason {
        /** Refresh failed or a second auth failure: converge to login. */
        AuthExhausted,
        /** Server revoked session/device: revalidate device state first. */
        Revoked,
        /** Foreground reconnect budget spent: manual Sync remains. */
        AttemptsExhausted,
    }

    /** Owner hooks. No hook may persist socket state. */
    interface Callbacks {
        /** One parsed realtime item: ingest via InboxProcessor.receiveOne. */
        suspend fun onItem(item: MailboxItem)

        /**
         * Single revalidation hook for STOMP auth failure, through the
         * existing SessionRefresher path. Null when unavailable: the
         * client then stops instead of retrying.
         */
        suspend fun refreshSession(): AuthSession?

        /** Terminal stop: owner revalidates or converges to login. */
        fun onStopped(reason: StopReason)
    }

    private enum class State {
        Idle,
        Connecting,
        Subscribed,
        Backoff,
    }

    internal companion object {
        const val DEVICE_TOPIC_PREFIX = "/topic/devices/"
        const val SUBSCRIPTION_ID = "sub-0"
        const val POLICY_VIOLATION_CODE = 1008
    }

    private val scope = CoroutineScope(parentScope.coroutineContext + SupervisorJob())

    @Volatile private var state: State = State.Idle
    @Volatile private var running: Boolean = false
    @Volatile private var generation: Long = 0
    private var socket: RealtimeSocket? = null
    private var reconnectJob: Job? = null
    private var reconnectAttempts: Int = 0
    private var refreshedOnce: Boolean = false
    private var current: StartParams? = null
    private var callbacks: Callbacks? = null

    private data class StartParams(
        val session: AuthSession,
        val serverAddress: String,
        val deviceId: String,
    )

    val isRunning: Boolean
        get() = running && state != State.Idle

    /**
     * Starts (or no-ops when already running) the foreground realtime
     * connection. The owner must have run ReconciliationSweep first and
     * must hold an adopted bound device id; the server enforces the
     * exact-subscription match regardless.
     */
    @Synchronized
    fun start(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
        callbacks: Callbacks,
    ) {
        require(serverAddress.startsWith("https://")) { "HTTPS server address only" }
        require(deviceId.isNotBlank()) { "bound device id required" }
        require(session.accessToken.isNotBlank()) { "access token required" }
        if (running) return
        running = true
        reconnectAttempts = 0
        refreshedOnce = false
        current = StartParams(session, serverAddress, deviceId)
        this.callbacks = callbacks
        openSocket(session.accessToken)
    }

    /** Idempotent foreground-scope exit: DISCONNECT, close, cancel waits. */
    @Synchronized
    fun stop() {
        running = false
        reconnectJob?.cancel()
        reconnectJob = null
        state = State.Idle
        current = null
        callbacks = null
        try {
            socket?.send(StompFrame.buildDisconnect())
        } catch (_: Exception) {
            // Best-effort goodbye on a dying transport.
        }
        try {
            socket?.close()
        } catch (_: Exception) {
            // Close must never throw out of lifecycle teardown.
        }
        socket = null
    }

    @Synchronized
    private fun openSocket(accessToken: String) {
        val params = current ?: return
        val host = params.serverAddress.removePrefix("https://").trimEnd('/')
        val uri = try {
            URI("wss://$host/ws")
        } catch (e: Exception) {
            throw IllegalArgumentException("unusable server address", e)
        }
        val gen = ++generation
        state = State.Connecting
        val fresh = object : SocketEvents {
            override fun onOpen() = handleOpen(gen, accessToken)
            override fun onText(text: String) = handleText(gen, text)
            override fun onClosed(code: Int, remote: Boolean) = handleClosed(gen, code)
            override fun onTransportError() = handleTransportError(gen)
        }
        val created = socketFactory(uri, fresh)
        socket = created
        try {
            created.connect()
        } catch (_: Exception) {
            // Synchronous connect failure behaves like transport loss.
            handleTransportError(gen)
        }
    }

    private fun expectedDestination(): String? =
        current?.let { DEVICE_TOPIC_PREFIX + it.deviceId }

    private fun handleOpen(gen: Long, accessToken: String) {
        val host: String?
        synchronized(this) {
            if (gen != generation || state != State.Connecting) return
            host = current?.serverAddress?.removePrefix("https://")?.trimEnd('/')
        }
        host ?: return
        try {
            socket?.send(StompFrame.buildConnect(host, accessToken))
        } catch (_: Exception) {
            handleTransportError(gen)
        }
    }

    private fun handleText(gen: Long, text: String) {
        val frame = StompFrame.parse(text) ?: return
        when (frame.command) {
            StompFrame.Command.CONNECTED -> handleConnected(gen)
            StompFrame.Command.MESSAGE -> handleMessage(gen, frame)
            StompFrame.Command.ERROR -> handleError(gen)
            else -> Unit
        }
    }

    private fun handleConnected(gen: Long) {
        val destination: String?
        synchronized(this) {
            if (gen != generation || state != State.Connecting) return
            destination = expectedDestination()
            state = State.Subscribed
            reconnectAttempts = 0
        }
        destination ?: return
        try {
            socket?.send(StompFrame.buildSubscribe(destination, SUBSCRIPTION_ID))
        } catch (_: Exception) {
            handleTransportError(gen)
        }
    }

    private fun handleMessage(gen: Long, frame: StompFrame.Frame) {
        val callbacks: Callbacks?
        synchronized(this) {
            if (gen != generation || state != State.Subscribed) return
            if (frame.headers["destination"] != expectedDestination()) return
            callbacks = this.callbacks
        }
        val item = try {
            parseMailboxItem(JSONObject(frame.body))
        } catch (_: JSONException) {
            return
        }
        callbacks ?: return
        scope.launch {
            try {
                callbacks.onItem(item)
            } catch (_: Exception) {
                // Ingest failures stay local: the mailbox row remains and
                // the next sweep recovers it. Never kill the socket here.
            }
        }
    }

    private fun handleError(gen: Long) {
        val preSubscription: Boolean
        val awaitedGen: Long
        synchronized(this) {
            if (gen != generation || (state != State.Connecting && state != State.Subscribed)) return
            preSubscription = state == State.Connecting
            invalidateSocketLocked()
            // The invalidation above advanced the generation: the refresh
            // reconnect below must expect the NEW generation, not the dead
            // socket's.
            awaitedGen = generation
            if (!preSubscription) {
                // Post-subscription ERROR is a server decision (revoked
                // session/device), never a retryable transport event.
                terminateLocked(StopReason.Revoked)
                return
            }
            if (refreshedOnce) {
                // Pre-subscription ERROR after the single refresh already
                // ran: stop and converge to login instead of looping.
                terminateLocked(StopReason.AuthExhausted)
                return
            }
            refreshedOnce = true
        }
        // Single revalidation through the existing session path, then at
        // most one reconnect with the fresh token.
        scope.launch {
            val fresh = try {
                callbacksSnapshot()?.refreshSession()
            } catch (_: Exception) {
                null
            }
            synchronized(this@RealtimeInbox) {
                if (!running || awaitedGen != generation) return@synchronized
                if (fresh == null || fresh.accessToken.isBlank()) {
                    terminateLocked(StopReason.AuthExhausted)
                    return@synchronized
                }
                current = current?.copy(session = fresh)
                reconnectAttempts = 0
                openSocket(fresh.accessToken)
            }
        }
    }

    private fun handleClosed(gen: Long, code: Int) {
        synchronized(this) {
            if (gen != generation || !running) return
            if (state == State.Idle) return
            invalidateSocketLocked()
            if (code == POLICY_VIOLATION_CODE) {
                // Server tore down a revoked session/device: revalidate
                // authoritative state before any new connection.
                terminateLocked(StopReason.Revoked)
                return
            }
            scheduleReconnectLocked()
        }
    }

    private fun handleTransportError(gen: Long) {
        synchronized(this) {
            if (gen != generation || !running) return
            if (state == State.Idle) return
            invalidateSocketLocked()
            scheduleReconnectLocked()
        }
    }

    /** Drops the current socket without reporting: a successor follows. */
    private fun invalidateSocketLocked() {
        generation++
        try {
            socket?.close()
        } catch (_: Exception) {
            // Dying transports must not break the state machine.
        }
        socket = null
    }

    private fun scheduleReconnectLocked() {
        if (!running || state == State.Idle) return
        if (reconnectAttempts >= maxReconnectAttempts) {
            terminateLocked(StopReason.AttemptsExhausted)
            return
        }
        val shift = min(reconnectAttempts, 10)
        val exponential = baseDelayMillis * (1L shl shift)
        val capped = min(exponential, maxDelayMillis)
        val wait = capped + jitter(jitterBoundMillis)
        reconnectAttempts++
        state = State.Backoff
        val params = current ?: run {
            terminateLocked(StopReason.AttemptsExhausted)
            return
        }
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            delay(wait)
            synchronized(this@RealtimeInbox) {
                if (!running || state != State.Backoff) return@synchronized
                openSocket(params.session.accessToken)
            }
        }
    }

    private fun terminateLocked(reason: StopReason) {
        val callbacks = callbacks
        running = false
        reconnectJob?.cancel()
        reconnectJob = null
        state = State.Idle
        current = null
        this.callbacks = null
        try {
            socket?.close()
        } catch (_: Exception) {
            // Teardown must not throw.
        }
        socket = null
        try {
            callbacks?.onStopped(reason)
        } catch (_: Exception) {
            // Owner notification must not break teardown.
        }
    }

    @Synchronized
    private fun callbacksSnapshot(): Callbacks? = callbacks

    /**
     * Default socket: Java-WebSocket with NO custom factory, so wss uses
     * the platform default SSLSocketFactory and the Network Security
     * Config trust anchors apply untouched (proven by
     * RealtimeTlsInstrumentedTest). No custom TrustManager, no hostname
     * bypass, no cleartext — ever.
     */
    private class JavaWebSocketSocket(
        uri: URI,
        private val events: SocketEvents,
    ) : RealtimeSocket {
        private val client = object : WebSocketClient(uri) {
            override fun onOpen(handshakedata: ServerHandshake?) = events.onOpen()
            override fun onMessage(message: String?) {
                if (message != null) events.onText(message)
            }

            override fun onClose(code: Int, reason: String?, remote: Boolean) =
                events.onClosed(code, remote)

            override fun onError(ex: Exception?) = events.onTransportError()
        }

        override fun connect() = client.connect()
        override fun send(text: String) = client.send(text)
        override fun close() {
            try {
                client.close()
            } catch (_: Exception) {
                // Best-effort teardown.
            }
        }
    }
}
