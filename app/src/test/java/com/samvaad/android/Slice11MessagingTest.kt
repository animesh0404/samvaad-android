package com.samvaad.android

import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.SendState
import com.samvaad.android.session.InboxResult
import com.samvaad.android.session.RecoverOutcome
import com.samvaad.android.session.SendFailure
import com.samvaad.android.session.SendResult
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.SweepReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 11 presentation-mapping tests: pure functions over durable rows.
 * No network, no crypto, no Room — openText/lookup lambdas stand in for
 * the sealer and session metadata. Plaintext-shaped values here are fake
 * test strings, never real content.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class Slice11MessagingTest {

    private fun row(
        messageId: String,
        conversationId: String = "conv-1",
        sequenceNumber: Long = 1L,
        direction: MessageDirection = MessageDirection.IN,
        sendState: SendState? = null,
        senderDeviceId: String = "sender-dev",
        recipientDeviceId: String = "recipient-dev",
        sealed: ByteArray? = "sealed".toByteArray(),
        serverTimestamp: String = "2026-10-02T10:00:00",
    ) = MessageEntity(
        messageId = messageId,
        conversationId = conversationId,
        sequenceNumber = sequenceNumber,
        direction = direction,
        senderDeviceId = senderDeviceId,
        recipientDeviceId = recipientDeviceId,
        envelopeType = "PREKEY_INIT",
        ciphertext = "cipher".toByteArray(),
        plaintextSealed = sealed,
        sendState = sendState,
        acked = false,
        requestId = null,
        serverTimestamp = serverTimestamp,
        createdAt = 1000L,
    )

    private val openEcho: (String, ByteArray) -> String? =
        { _, sealed -> String(sealed, Charsets.UTF_8) }

    private val previewEcho: (MessageEntity) -> String =
        { String(it.plaintextSealed!!, Charsets.UTF_8) }

    private fun cleanReport() = SweepReport(
        outboxRecovered = emptyList(),
        outboxSkippedDevices = emptyList(),
        outboxError = null,
        inbox = InboxResult.Completed(emptyList(), emptyList(), emptyList(), emptyList()),
        inboxError = null,
        historyStored = 0,
        historyDuplicates = 0,
        historySkipped = 0,
        historyError = null,
        cursorsAdvanced = emptyMap(),
        cursorError = null,
    )

    @Test
    fun list_emptyMap_yieldsEmpty() {
        val list = buildConversationList(emptyMap(), { id, _ -> id }, previewEcho)
        assertTrue(list.isEmpty())
    }

    @Test
    fun list_sentinelEmptyConversationId_excluded() {
        val out = row("m-1", conversationId = "", direction = MessageDirection.OUT, sendState = SendState.PENDING_SEAL)
        val list = buildConversationList(
            mapOf("" to listOf(out), "conv-1" to listOf(row("m-2"))),
            { id, _ -> id },
            previewEcho,
        )
        assertEquals(listOf("conv-1"), list.map { it.conversationId })
    }

    @Test
    fun list_previewUsesLatestDurableSequence_orderedDescending() {
        val conv1 = listOf(row("a", "conv-1", 1L), row("b", "conv-1", 2L))
        val conv2 = listOf(row("c", "conv-2", 5L))
        val list = buildConversationList(
            mapOf("conv-1" to conv1, "conv-2" to conv2),
            { id, _ -> id },
            previewEcho,
        )
        assertEquals(listOf("conv-2", "conv-1"), list.map { it.conversationId })
        assertEquals(5L, list[0].previewSequence)
        assertEquals(2L, list[1].previewSequence)
        // Preview text comes from the latest row's sealed content.
        assertEquals("sealed", list[0].previewText)
    }

    @Test
    fun list_hasPending_onlyForUnacceptedOutbound() {
        val pending = mapOf(
            "p" to listOf(row("m-1", "p", 1L, MessageDirection.OUT, SendState.PENDING_SEAL)),
            "s" to listOf(row("m-2", "s", 3L, MessageDirection.OUT, SendState.SEALED)),
            "d" to listOf(row("m-3", "d", 7L, MessageDirection.OUT, SendState.SENT)),
            "i" to listOf(row("m-4", "i", 9L)),
        )
        val byId = buildConversationList(pending, { id, _ -> id }, previewEcho)
            .associateBy { it.conversationId }
        assertTrue(byId.getValue("p").hasPending)
        assertTrue(byId.getValue("s").hasPending)
        assertFalse(byId.getValue("d").hasPending)
        assertFalse(byId.getValue("i").hasPending)
    }

    @Test
    fun list_emptyGroup_skipped() {
        val list = buildConversationList(
            mapOf("conv-1" to emptyList(), "conv-2" to listOf(row("m-1", "conv-2"))),
            { id, _ -> id },
            previewEcho,
        )
        assertEquals(listOf("conv-2"), list.map { it.conversationId })
    }

    @Test
    fun row_outboundStates_mapToSendingOrSent() {
        val pending = mapMessageRow(
            row("m-1", direction = MessageDirection.OUT, sendState = SendState.PENDING_SEAL),
            OWN_SENDER_LABEL, openEcho
        )
        val sealed = mapMessageRow(
            row("m-2", direction = MessageDirection.OUT, sendState = SendState.SEALED),
            OWN_SENDER_LABEL, openEcho
        )
        val sent = mapMessageRow(
            row("m-3", direction = MessageDirection.OUT, sendState = SendState.SENT),
            OWN_SENDER_LABEL, openEcho
        )
        assertEquals(SENDING_LABEL, pending.meta)
        assertEquals(SENDING_LABEL, sealed.meta)
        assertEquals("2026-10-02T10:00:00", sent.meta)
        assertTrue(pending.isOutbound)
        assertEquals(OWN_SENDER_LABEL, sent.senderLabel)
    }

    @Test
    fun row_inbound_showsTimestampWithoutState() {
        val mapped = mapMessageRow(row("m-1", sequenceNumber = 4L), "bob", openEcho)
        assertEquals("2026-10-02T10:00:00", mapped.meta)
        assertEquals(4L, mapped.sequenceNumber)
        assertEquals("bob", mapped.senderLabel)
        assertFalse(mapped.isOutbound)
        assertEquals("sealed", mapped.text)
    }

    @Test
    fun row_unsealFailure_rendersPlaceholder() {
        val nullOpen: (String, ByteArray) -> String? = { _, _ -> null }
        val blankOpen: (String, ByteArray) -> String? = { _, _ -> "" }
        assertEquals(
            MESSAGE_UNREADABLE,
            mapMessageRow(row("m-1"), "bob", nullOpen).text
        )
        assertEquals(
            MESSAGE_UNREADABLE,
            mapMessageRow(row("m-1"), "bob", blankOpen).text
        )
        assertEquals(
            MESSAGE_UNREADABLE,
            mapMessageRow(row("m-2", sealed = null), "bob", openEcho).text
        )
    }

    @Test
    fun peerLabel_outboundUsesRecipient_inboundUsesSender() {
        val out = row("m-1", direction = MessageDirection.OUT, recipientDeviceId = "dev-bob")
        assertEquals(
            "bob",
            peerLabelFor("conv-1", listOf(out)) { if (it == "dev-bob") "bob" else null }
        )
        val inbound = row("m-2", senderDeviceId = "dev-bob")
        assertEquals(
            "bob",
            peerLabelFor("conv-1", listOf(inbound)) { if (it == "dev-bob") "bob" else null }
        )
    }

    @Test
    fun peerLabel_missingMetadata_fallsBackToConversationId() {
        assertEquals(
            "conv-9",
            peerLabelFor("conv-9", listOf(row("m-1", "conv-9"))) { null }
        )
        assertEquals("conv-9", peerLabelFor("conv-9", emptyList()) { "bob" })
    }

    @Test
    fun senderLabel_outboundIsYou_inboundResolvedOrUnknown() {
        val out = row("m-1", direction = MessageDirection.OUT)
        assertEquals(OWN_SENDER_LABEL, senderLabelFor(out) { "bob" })
        val inbound = row("m-2", senderDeviceId = "dev-bob")
        assertEquals("bob", senderLabelFor(inbound) { if (it == "dev-bob") "bob" else null })
        assertEquals(UNKNOWN_SENDER_LABEL, senderLabelFor(inbound) { null })
    }

    @Test
    fun sendFailures_mapToFixedLeakFreeMessages() {
        val kinds = listOf(
            SendFailure.CryptoUnavailable,
            SendFailure.SessionUnavailable("no-session"),
            SendFailure.IdentityMismatch,
            SendFailure.TransportRetryable,
            SendFailure.Unauthorized,
            SendFailure.Forbidden,
            SendFailure.NotFound,
            SendFailure.Conflict,
            SendFailure.BadRequest,
            SendFailure.Rejected("internal-reason-xyz"),
        )
        val messages = kinds.map(::sendFailureMessage)
        // Fixed strings only; several failures share one safe message.
        messages.forEach { assertTrue(it.isNotBlank()) }
        // Internal reasons never leak into user-visible text.
        assertFalse(messages.any { it.contains("internal-reason-xyz") })
        assertFalse(messages.any { it.contains("no-session") })
    }

    @Test
    fun establishFailures_mapToFixedMessages_nullOnEstablished() {
        assertNull(
            establishFailureMessage(
                SessionEstablishResult.Established(
                    entry = com.samvaad.android.session.SignalSessionEntry(
                        remoteDeviceId = "d",
                        remoteUsername = "bob",
                        remoteSignalDeviceId = 1,
                        remoteRegistrationId = 1,
                        remoteIdentityPublicKeyB64 = "eA==",
                        establishedVia = com.samvaad.android.session.EstablishedVia.WITH_OTPK,
                        localIdentityHandleId = "h",
                        createdAt = 0L,
                        updatedAt = 0L,
                    ),
                    reused = true,
                )
            )
        )
        val cases = mapOf<SessionEstablishResult, String>(
            SessionEstablishResult.NotFriends to "friends",
            SessionEstablishResult.TargetNotFound to "not found",
            SessionEstablishResult.Unauthorized to "sign-in",
            SessionEstablishResult.NoDevices to "no active devices",
        )
        cases.forEach { (result, fragment) ->
            val message = establishFailureMessage(result)
            assertTrue(message != null && message.contains(fragment, ignoreCase = true))
        }
        // Every other outcome maps to some fixed message.
        listOf(
            SessionEstablishResult.DeviceNotActive,
            SessionEstablishResult.ClaimConflict,
            SessionEstablishResult.KyberUnsupported,
            SessionEstablishResult.IdentityMismatch,
            SessionEstablishResult.CryptoUnavailable,
            SessionEstablishResult.TransportRetryable,
        ).forEach { assertTrue(establishFailureMessage(it)!!.isNotBlank()) }
    }

    @Test
    fun sweepReport_cleanMapsToNull_anyErrorMapsToMessage() {
        assertNull(sweepErrorMessage(cleanReport()))
        assertTrue(sweepErrorMessage(cleanReport().copy(outboxError = "outbox-recovery-failed")) != null)
        assertTrue(sweepErrorMessage(cleanReport().copy(inboxError = "inbox-failed")) != null)
        assertTrue(sweepErrorMessage(cleanReport().copy(historyError = "history-failed")) != null)
        assertTrue(sweepErrorMessage(cleanReport().copy(cursorError = "cursor-fetch-failed")) != null)
        // The sweep reports a null branch error when receive() returns
        // Failed instead of throwing: the failed result itself must surface.
        val inboxFailed = cleanReport().copy(
            inbox = InboxResult.Failed(
                com.samvaad.android.session.InboxFailure.TransportRetryable
            )
        )
        assertTrue(sweepErrorMessage(inboxFailed) != null)
        val rowFailed = cleanReport().copy(
            outboxRecovered = listOf(
                RecoverOutcome.RowFailed(
                    "m-1",
                    SendResult.Failed(SendFailure.Rejected("message-store-failed")),
                )
            )
        )
        assertTrue(sweepErrorMessage(rowFailed) != null)
    }
}
