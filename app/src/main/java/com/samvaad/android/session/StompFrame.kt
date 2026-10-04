package com.samvaad.android.session

/**
 * Minimal STOMP 1.2 frame codec for foreground realtime inbound only.
 *
 * Covered commands: CONNECT, CONNECTED, SUBSCRIBE, MESSAGE, ERROR,
 * DISCONNECT. There is intentionally NO SEND builder: the server
 * exposes no client SEND contract, so this client must never emit one.
 *
 * Heartbeats: the client advertises `heart-beat:0,0` (sends none,
 * expects none), matching the server's default broker configuration.
 * No heartbeat timers exist here.
 *
 * Nothing here logs frame bodies: MESSAGE bodies carry ciphertext and
 * must never reach logs.
 */
internal object StompFrame {

    /** STOMP commands this client can emit or must handle. No SEND. */
    enum class Command {
        CONNECT,
        CONNECTED,
        SUBSCRIBE,
        MESSAGE,
        ERROR,
        DISCONNECT,
        UNKNOWN,
    }

    data class Frame(
        val command: Command,
        val headers: Map<String, String>,
        val body: String,
    )

    private const val TERMINATOR = '\u0000'
    private const val HEART_BEAT_HEADER = "heart-beat"
    private const val NO_HEARTBEAT = "0,0"

    /**
     * Parses one raw frame. Returns null for malformed input (empty
     * command, malformed header line, missing NUL terminator): callers
     * ignore malformed frames without touching durable state.
     */
    fun parse(raw: String): Frame? {
        if (raw.isEmpty()) return null
        val withoutTerminator = if (raw.endsWith(TERMINATOR)) {
            raw.dropLast(1)
        } else {
            return null
        }
        // Command line, then headers until the first blank line; the
        // remainder is the body (an optional trailing newline after the
        // blank separator line is not part of the body).
        val headEnd = withoutTerminator.indexOf("\n\n")
        if (headEnd < 0) return null
        val head = withoutTerminator.substring(0, headEnd)
        var body = withoutTerminator.substring(headEnd + 2)
        if (body.startsWith("\n")) body = body.drop(1)
        val lines = head.split("\n")
        if (lines.isEmpty() || lines[0].isEmpty()) return null
        val command = try {
            Command.valueOf(lines[0].trim())
        } catch (_: IllegalArgumentException) {
            Command.UNKNOWN
        }
        val headers = LinkedHashMap<String, String>()
        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isEmpty()) return null
            val colon = line.indexOf(':')
            if (colon <= 0) return null
            headers[line.substring(0, colon)] = line.substring(colon + 1)
        }
        return Frame(command, headers, body)
    }

    /** Serializes a frame with the mandatory NUL terminator. */
    fun serialize(command: Command, headers: Map<String, String>, body: String = ""): String {
        require(command != Command.UNKNOWN) { "cannot serialize UNKNOWN" }
        require(command != Command.CONNECTED && command != Command.MESSAGE && command != Command.ERROR) {
            "client never emits $command"
        }
        val out = StringBuilder(command.name).append('\n')
        for ((name, value) in headers) {
            require(name.isNotEmpty() && '\n' !in name && ':' !in name) { "bad header name" }
            require('\n' !in value) { "bad header value" }
            out.append(name).append(':').append(value).append('\n')
        }
        out.append('\n').append(body).append(TERMINATOR)
        return out.toString()
    }

    fun buildConnect(host: String, bearerToken: String): String {
        require(host.isNotBlank()) { "host required" }
        require(bearerToken.isNotBlank()) { "bearer token required" }
        return serialize(
            Command.CONNECT,
            mapOf(
                "accept-version" to "1.2",
                "host" to host,
                "Authorization" to "Bearer $bearerToken",
                HEART_BEAT_HEADER to NO_HEARTBEAT,
            ),
        )
    }

    fun buildSubscribe(destination: String, subscriptionId: String = "sub-0"): String {
        require(destination.isNotBlank()) { "destination required" }
        require(subscriptionId.isNotBlank()) { "subscription id required" }
        return serialize(
            Command.SUBSCRIBE,
            mapOf(
                "id" to subscriptionId,
                "destination" to destination,
            ),
        )
    }

    fun buildDisconnect(): String = serialize(Command.DISCONNECT, emptyMap())
}
