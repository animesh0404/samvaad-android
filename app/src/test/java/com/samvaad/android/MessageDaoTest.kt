package com.samvaad.android

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.db.ConversationEntity
import com.samvaad.android.db.MessageDao
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.SendState
import com.samvaad.android.db.highestContiguous
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Message-state DAO tests against an in-memory Room database
 * (Robolectric host leg). Covers every query the crash-recovery state
 * machines depend on, plus the contiguity rule that guards cursor
 * advancement. No network, no Keystore, no UI.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class MessageDaoTest {

    private lateinit var db: MessageDatabase
    private lateinit var dao: MessageDao

    @Before
    fun setUp() {
        val context: Context = ApplicationProvider.getApplicationContext()
        db = Room.inMemoryDatabaseBuilder(context, MessageDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = db.messageDao()
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun message(
        messageId: String,
        conversationId: String = "conv-1",
        sequenceNumber: Long = 1L,
        direction: MessageDirection = MessageDirection.IN,
        sendState: SendState? = null,
        acked: Boolean = false,
        requestId: String? = null,
    ) = MessageEntity(
        messageId = messageId,
        conversationId = conversationId,
        sequenceNumber = sequenceNumber,
        direction = direction,
        senderDeviceId = "sender-dev",
        recipientDeviceId = "recipient-dev",
        envelopeType = "PREKEY_INIT",
        ciphertext = "cipher".toByteArray(),
        plaintextSealed = "sealed".toByteArray(),
        sendState = sendState,
        acked = acked,
        requestId = requestId,
        serverTimestamp = "2026-10-02T10:00:00",
        createdAt = 1000L,
    )

    @Test
    fun conversation_insertReadAndState() = runBlocking {
        assertNull(dao.conversation("conv-1"))
        dao.upsertConversation(ConversationEntity("conv-1"))
        assertEquals(ConversationEntity("conv-1", 0L, 0L), dao.conversation("conv-1"))
        dao.setLastSeen("conv-1", 7L)
        dao.setCursor("conv-1", 5L)
        assertEquals(ConversationEntity("conv-1", 7L, 5L), dao.conversation("conv-1"))
        // Upsert replaces the row.
        dao.upsertConversation(ConversationEntity("conv-1", 9L, 9L))
        assertEquals(ConversationEntity("conv-1", 9L, 9L), dao.conversation("conv-1"))
    }

    @Test
    fun message_insertRead_roundTrip() = runBlocking {
        val row = message("m-1")
        dao.insertIgnore(row)
        val back = dao.byMessageId("m-1")!!
        // ByteArray columns use referential equality: compare BLOB
        // contents explicitly, everything else by data-class equality.
        assertArrayEquals(row.ciphertext, back.ciphertext)
        assertArrayEquals(row.plaintextSealed, back.plaintextSealed)
        assertEquals(row.conversationId, back.conversationId)
        assertEquals(row.sequenceNumber, back.sequenceNumber)
        assertEquals(row.direction, back.direction)
        assertEquals(row.senderDeviceId, back.senderDeviceId)
        assertEquals(row.recipientDeviceId, back.recipientDeviceId)
        assertEquals(row.envelopeType, back.envelopeType)
        assertEquals(row.sendState, back.sendState)
        assertEquals(row.acked, back.acked)
        assertEquals(row.requestId, back.requestId)
        assertEquals(row.serverTimestamp, back.serverTimestamp)
        assertEquals(row.createdAt, back.createdAt)
        assertNull(dao.byMessageId("missing"))
    }

    @Test
    fun duplicateMessageId_absorbed() = runBlocking {
        assertTrue(dao.insertIgnore(message("m-1", sequenceNumber = 1L)) != -1L)
        // Same messageId, different content: absorbed, original kept.
        assertEquals(-1L, dao.insertIgnore(message("m-1", sequenceNumber = 2L)))
        assertEquals(1L, dao.byMessageId("m-1")!!.sequenceNumber)
    }

    @Test
    fun duplicateSequence_differentIds_bothStored() = runBlocking {
        // The server contract guarantees sequence uniqueness; the local
        // layer keys dedupe on messageId only and stores what it is given
        // rather than second-guessing the server with a hard failure.
        dao.insertIgnore(message("m-1", sequenceNumber = 1L))
        dao.insertIgnore(message("m-2", sequenceNumber = 1L))
        assertEquals(2, dao.historyPage("conv-1", 0L, 10).size)
    }

    @Test
    fun requestId_lookupAndUniqueness() = runBlocking {
        dao.insertIgnore(message("m-1", direction = MessageDirection.OUT, requestId = "req-1"))
        assertEquals("m-1", dao.byRequestId("req-1")!!.messageId)
        assertNull(dao.byRequestId("req-missing"))
    }

    @Test
    fun markTransitions_updateRows() = runBlocking {
        dao.insertIgnore(
            message("m-1", direction = MessageDirection.OUT, sendState = SendState.PENDING_SEAL, requestId = "req-1")
        )
        assertEquals(1, dao.markSealed("m-1"))
        assertEquals(SendState.SEALED, dao.byMessageId("m-1")!!.sendState)
        assertEquals(1, dao.markSent("m-1"))
        assertEquals(SendState.SENT, dao.byMessageId("m-1")!!.sendState)
        assertEquals(1, dao.markAcked("m-1"))
        assertEquals(true, dao.byMessageId("m-1")!!.acked)
        // Unknown IDs touch nothing instead of failing.
        assertEquals(0, dao.markSealed("missing"))
        assertEquals(0, dao.markSent("missing"))
        assertEquals(0, dao.markAcked("missing"))
    }

    @Test
    fun pendingOutbox_listsUnsubmittedOutboundOnly() = runBlocking {
        dao.insertIgnore(message("o-pending", direction = MessageDirection.OUT, sendState = SendState.PENDING_SEAL))
        dao.insertIgnore(message("o-sealed", direction = MessageDirection.OUT, sendState = SendState.SEALED))
        dao.insertIgnore(message("o-sent", direction = MessageDirection.OUT, sendState = SendState.SENT))
        dao.insertIgnore(message("i-unacked", direction = MessageDirection.IN, acked = false))
        val pending = dao.pendingOutbox().map { it.messageId }.toSet()
        assertEquals(setOf("o-pending", "o-sealed"), pending)
    }

    @Test
    fun unacked_listsUnackedInboundOnly() = runBlocking {
        dao.insertIgnore(message("i-open", direction = MessageDirection.IN, acked = false))
        dao.insertIgnore(message("i-done", direction = MessageDirection.IN, acked = true))
        dao.insertIgnore(message("o-sealed", direction = MessageDirection.OUT, sendState = SendState.SEALED))
        assertEquals(listOf("i-open"), dao.unacked().map { it.messageId })
    }

    @Test
    fun historyPage_ordersAndFilters() = runBlocking {
        dao.insertIgnore(message("m-3", sequenceNumber = 3L))
        dao.insertIgnore(message("m-1", sequenceNumber = 1L))
        dao.insertIgnore(message("m-2", sequenceNumber = 2L))
        dao.insertIgnore(message("m-other", conversationId = "conv-2", sequenceNumber = 1L))
        val page = dao.historyPage("conv-1", 0L, 10)
        assertEquals(listOf(1L, 2L, 3L), page.map { it.sequenceNumber })
        assertEquals(listOf(2L, 3L), dao.historyPage("conv-1", 1L, 10).map { it.sequenceNumber })
        assertEquals(listOf(1L, 2L), dao.historyPage("conv-1", 0L, 2).map { it.sequenceNumber })
        assertEquals(listOf("m-other"), dao.historyPage("conv-2", 0L, 10).map { it.messageId })
        assertTrue(dao.historyPage("conv-1", 3L, 10).isEmpty())
    }

    @Test
    fun sequencesFor_supportsContiguity() = runBlocking {
        dao.insertIgnore(message("m-3", sequenceNumber = 3L))
        dao.insertIgnore(message("m-1", sequenceNumber = 1L))
        dao.insertIgnore(message("m-2", sequenceNumber = 2L))
        dao.insertIgnore(message("m-5", sequenceNumber = 5L))
        assertEquals(listOf(1L, 2L, 3L, 5L), dao.sequencesFor("conv-1"))
        assertEquals(3L, highestContiguous(dao.sequencesFor("conv-1")))
    }

    @Test
    fun highestContiguous_documentedCases() {
        assertEquals(3L, highestContiguous(listOf(1L, 2L, 3L)))
        assertEquals(3L, highestContiguous(listOf(3L, 1L, 2L, 5L)))
        assertEquals(3L, highestContiguous(listOf(1L, 2L, 3L, 5L)))
        assertEquals(1L, highestContiguous(listOf(1L, 3L)))
        assertEquals(1L, highestContiguous(listOf(1L)))
        // A gap stops advancement: callers must gap-fill first.
        assertEquals(0L, highestContiguous(emptyList()))
        assertEquals(0L, highestContiguous(listOf(2L, 3L)))
        // A set starting past 1 has no verified prefix: the reconciler
        // owns gap handling, not this pure function — it reports 0.
        assertEquals(0L, highestContiguous(listOf(5L, 6L)))
        // Duplicates are absorbed, not advanced past.
        assertEquals(3L, highestContiguous(listOf(1L, 2L, 2L, 3L)))
        assertNotEquals(6L, highestContiguous(listOf(1L, 2L, 3L, 5L, 6L)))
    }
}
