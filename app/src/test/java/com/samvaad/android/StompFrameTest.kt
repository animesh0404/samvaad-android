package com.samvaad.android

import com.samvaad.android.session.StompFrame
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Slice 13 STOMP codec tests: the minimal CONNECT/CONNECTED/SUBSCRIBE/
 * MESSAGE/ERROR/DISCONNECT subset. Pure JVM, no network, no crypto.
 *
 * There is intentionally no SEND coverage: the codec must not offer it
 * (the server has no client SEND contract).
 */
class StompFrameTest {

    @Test
    fun buildConnect_carriesBearerAndHeartbeatOff() {
        val frame = StompFrame.buildConnect("192.168.29.41:8080", "access-1")
        assertTrue(frame.startsWith("CONNECT\n"))
        assertTrue(frame.contains("\nAuthorization:Bearer access-1\n"))
        assertTrue(frame.contains("\naccept-version:1.2\n"))
        assertTrue(frame.contains("\nhost:192.168.29.41:8080\n"))
        assertTrue(frame.contains("\nheart-beat:0,0\n"))
        assertTrue(frame.endsWith("\n\n\u0000"))
    }

    @Test
    fun buildSubscribe_exactOwnDestination() {
        val frame = StompFrame.buildSubscribe("/topic/devices/dev-9")
        assertTrue(frame.startsWith("SUBSCRIBE\n"))
        assertTrue(frame.contains("\nid:sub-0\n"))
        assertTrue(frame.contains("\ndestination:/topic/devices/dev-9\n"))
        assertTrue(frame.endsWith("\n\n\u0000"))
    }

    @Test
    fun buildSubscribe_rejectsBlankDestination() {
        try {
            StompFrame.buildSubscribe("  ")
            throw AssertionError("expected rejection")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("destination"))
        }
    }

    @Test
    fun buildConnect_rejectsBlankToken() {
        try {
            StompFrame.buildConnect("host", "  ")
            throw AssertionError("expected rejection")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("bearer"))
        }
    }

    @Test
    fun parse_connectedWithHeartbeat() {
        val frame = StompFrame.parse("CONNECTED\nversion:1.2\nheart-beat:0,0\n\n\u0000")
        assertEquals(StompFrame.Command.CONNECTED, frame!!.command)
        assertEquals("0,0", frame.headers["heart-beat"])
        assertEquals("", frame.body)
    }

    @Test
    fun parse_messageWithJsonBody() {
        val body = "{\"messageId\":\"m-1\"}"
        val frame = StompFrame.parse(
            "MESSAGE\nsubscription:sub-0\ndestination:/topic/devices/d-1\n" +
                "content-length:${body.length}\n\n$body\u0000",
        )
        assertEquals(StompFrame.Command.MESSAGE, frame!!.command)
        assertEquals("/topic/devices/d-1", frame.headers["destination"])
        assertEquals(body, frame.body)
    }

    @Test
    fun parse_errorCarriesMessage() {
        val frame = StompFrame.parse("ERROR\nmessage:Forbidden\n\nAccess denied\u0000")
        assertEquals(StompFrame.Command.ERROR, frame!!.command)
        assertEquals("Forbidden", frame.headers["message"])
        assertEquals("Access denied", frame.body)
    }

    @Test
    fun parse_malformed_returnsNull() {
        assertNull(StompFrame.parse(""))
        assertNull(StompFrame.parse("MESSAGE\nno-terminator"))
        assertNull(StompFrame.parse("MESSAGE\nbad-header-line\n\nbody\u0000"))
        assertNull(StompFrame.parse("\n\n\u0000"))
        assertNull(StompFrame.parse("MESSAGE"))
    }

    @Test
    fun parse_unknownCommand_surfacedNotThrown() {
        val frame = StompFrame.parse("RECEIPT\nreceipt-id:1\n\n\u0000")
        assertEquals(StompFrame.Command.UNKNOWN, frame!!.command)
    }

    @Test
    fun serialize_refusesServerOnlyCommands() {
        for (command in
            listOf(
                StompFrame.Command.CONNECTED,
                StompFrame.Command.MESSAGE,
                StompFrame.Command.ERROR,
                StompFrame.Command.UNKNOWN,
            )) {
            try {
                StompFrame.serialize(command, emptyMap())
                throw AssertionError("expected refusal for $command")
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!.isNotEmpty())
            }
        }
    }

    @Test
    fun commandSet_hasNoSend() {
        assertEquals(
            setOf("CONNECT", "CONNECTED", "SUBSCRIBE", "MESSAGE", "ERROR", "DISCONNECT", "UNKNOWN"),
            StompFrame.Command.values().map { it.name }.toSet(),
        )
    }

    @Test
    fun buildDisconnect_isBareTerminated() {
        assertEquals("DISCONNECT\n\n\u0000", StompFrame.buildDisconnect())
    }
}
