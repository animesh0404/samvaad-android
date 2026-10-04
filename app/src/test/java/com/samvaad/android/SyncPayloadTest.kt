package com.samvaad.android

import com.samvaad.android.session.SyncPayloadMalformedException
import com.samvaad.android.session.buildSyncPayload
import com.samvaad.android.session.parseSyncPayload
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Sync payload format tests: canonical round-trip plus fail-closed
 * rejection of every malformed shape. No crypto involved — this is the
 * plaintext structure the Primary encrypts and the Companion validates
 * after decryption.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SyncPayloadTest {

    private fun payloadBytes() = buildSyncPayload(
        conversationId = "44444444-4444-4444-4444-444444444444",
        messageId = "11111111-1111-1111-1111-111111111111",
        sequenceNumber = 12L,
        senderDeviceId = "22222222-2222-3333-4444-555555555555",
        recipientDeviceId = "33333333-3333-3333-3333-333333333333",
        serverTimestamp = "2026-10-03T10:00:00",
        plaintext = "sync-plaintext".toByteArray(Charsets.UTF_8),
        frontier = 15L,
    )

    @Test
    fun roundTrip_preservesAllFields() {
        val parsed = parseSyncPayload(payloadBytes())
        assertEquals("44444444-4444-4444-4444-444444444444", parsed.conversationId)
        assertEquals("11111111-1111-1111-1111-111111111111", parsed.messageId)
        assertEquals(12L, parsed.sequenceNumber)
        assertEquals("22222222-2222-3333-4444-555555555555", parsed.senderDeviceId)
        assertEquals("33333333-3333-3333-3333-333333333333", parsed.recipientDeviceId)
        assertEquals("2026-10-03T10:00:00", parsed.serverTimestamp)
        assertEquals("sync-plaintext", parsed.plaintext.toString(Charsets.UTF_8))
        assertEquals(15L, parsed.frontier)
    }

    @Test
    fun wrongVersion_rejected() {
        val tampered = JSONObject(payloadBytes().toString(Charsets.UTF_8))
            .put("v", 999)
            .toString().toByteArray(Charsets.UTF_8)
        assertThrows(SyncPayloadMalformedException::class.java) {
            parseSyncPayload(tampered)
        }
    }

    @Test
    fun missingVersion_rejected() {
        val tampered = JSONObject(payloadBytes().toString(Charsets.UTF_8))
        tampered.remove("v")
        assertThrows(SyncPayloadMalformedException::class.java) {
            parseSyncPayload(tampered.toString().toByteArray(Charsets.UTF_8))
        }
    }

    @Test
    fun blankIdentity_rejected() {
        val tampered = JSONObject(payloadBytes().toString(Charsets.UTF_8))
            .put("senderDeviceId", "")
            .toString().toByteArray(Charsets.UTF_8)
        assertThrows(SyncPayloadMalformedException::class.java) {
            parseSyncPayload(tampered)
        }
    }

    @Test
    fun badBase64_rejected() {
        val tampered = JSONObject(payloadBytes().toString(Charsets.UTF_8))
            .put("plaintextBase64", "not-base64!!")
            .toString().toByteArray(Charsets.UTF_8)
        assertThrows(SyncPayloadMalformedException::class.java) {
            parseSyncPayload(tampered)
        }
    }

    @Test
    fun emptyPlaintext_rejected() {
        assertThrows(IllegalArgumentException::class.java) {
            buildSyncPayload(
                conversationId = "44444444-4444-4444-4444-444444444444",
                messageId = "11111111-1111-1111-1111-111111111111",
                sequenceNumber = 1L,
                senderDeviceId = "22222222-2222-3333-4444-555555555555",
                recipientDeviceId = "33333333-3333-3333-3333-333333333333",
                serverTimestamp = "2026-10-03T10:00:00",
                plaintext = ByteArray(0),
                frontier = 1L,
            )
        }
    }

    @Test
    fun frontierBelowSequence_rejectedBothWays() {
        assertThrows(IllegalArgumentException::class.java) {
            buildSyncPayload(
                conversationId = "44444444-4444-4444-4444-444444444444",
                messageId = "11111111-1111-1111-1111-111111111111",
                sequenceNumber = 5L,
                senderDeviceId = "22222222-2222-3333-4444-555555555555",
                recipientDeviceId = "33333333-3333-3333-3333-333333333333",
                serverTimestamp = "2026-10-03T10:00:00",
                plaintext = "x".toByteArray(Charsets.UTF_8),
                frontier = 4L,
            )
        }
        val tampered = JSONObject(payloadBytes().toString(Charsets.UTF_8))
            .put("frontier", 3L)
            .toString().toByteArray(Charsets.UTF_8)
        assertThrows(SyncPayloadMalformedException::class.java) {
            parseSyncPayload(tampered)
        }
    }

    @Test
    fun nonJson_rejected() {
        assertThrows(SyncPayloadMalformedException::class.java) {
            parseSyncPayload("not json at all".toByteArray(Charsets.UTF_8))
        }
    }

    @Test
    fun tamperedSequence_detectableByCaller() {
        // The parser accepts a well-formed payload with any sequence;
        // binding against the wire item is the caller's (ingest) job.
        // This test pins that the parsed value is exactly what was
        // encoded, so a mismatch is always observable.
        val tampered = JSONObject(payloadBytes().toString(Charsets.UTF_8))
            .put("sequenceNumber", 13L)
            .toString().toByteArray(Charsets.UTF_8)
        val parsed = parseSyncPayload(tampered)
        assertEquals(13L, parsed.sequenceNumber)
        assertTrue(parsed.messageId == "11111111-1111-1111-1111-111111111111")
    }
}
