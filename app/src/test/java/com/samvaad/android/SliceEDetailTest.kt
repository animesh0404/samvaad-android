package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToIndex
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.db.ConversationEntity
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.SendState
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.AttachBegin
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.HistoryItem
import com.samvaad.android.enroll.MailboxItem
import com.samvaad.android.enroll.MessageEnvelopeSubmit
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.enroll.SyncAckResult
import com.samvaad.android.enroll.SyncBatchItem
import com.samvaad.android.enroll.SyncCursor
import com.samvaad.android.enroll.SyncUploadRequest
import com.samvaad.android.enroll.SyncUploadResult
import com.samvaad.android.friends.FriendEntry
import com.samvaad.android.friends.FriendRequestRecord
import com.samvaad.android.friends.FriendsApi
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.SignalSessionEntry
import com.samvaad.android.ui.shell.SamvaadAppShell
import com.samvaad.android.ui.theme.SamvaadTheme
import com.samvaad.android.ui.util.formatServerTimestamp
import com.samvaad.android.ui.util.messageDayLabel
import java.io.File
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice E Chat Detail tests (host-side via Robolectric).
 *
 * Direct [ChatDetailScreen] renders cover bubbles/states/separators
 * with fabricated rows (no network, no crypto); the pure day-label and
 * mapping rules are covered without Compose; the shell-integrated flow
 * proves the new screen mounts through the real loader with file-backed
 * Room. Typed strings here are fake sentinels.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceEDetailTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun row(
        messageId: String = "m-1",
        isOutbound: Boolean = false,
        senderLabel: String = "bob",
        text: String = "hello-e",
        sequenceNumber: Long = 1L,
        serverTimestamp: String = "not-a-date-e",
    ): MessageRow {
        val meta = if (isOutbound && serverTimestamp.isEmpty()) {
            SENDING_LABEL
        } else {
            serverTimestamp.ifEmpty { "Sent" }
        }
        return MessageRow(
            messageId = messageId,
            isOutbound = isOutbound,
            senderLabel = senderLabel,
            text = text,
            sequenceNumber = sequenceNumber,
            meta = meta,
            serverTimestamp = serverTimestamp,
        )
    }

    private fun render(
        peerLabel: String = "bob",
        messages: List<MessageRow>? = emptyList(),
        loadError: String? = null,
        syncing: Boolean = false,
        syncError: String? = null,
        onRetry: () -> Unit = {},
        onSync: () -> Unit = {},
        composer: @androidx.compose.runtime.Composable () -> Unit = {},
    ) {
        composeTestRule.setContent {
            SamvaadTheme {
                ChatDetailScreen(
                    peerLabel = peerLabel,
                    messages = messages,
                    loadError = loadError,
                    onRetryLoad = onRetry,
                    syncing = syncing,
                    syncError = syncError,
                    onSync = onSync,
                    composer = composer,
                )
            }
        }
    }

    // ---- Pure day labels ----

    private val zone = ZoneId.of("UTC")
    // 2026-10-06T12:00:00Z: 2026-01-01T00:00Z (1767225600) + 278 days +
    // 12 hours, in millis.
    private val now = 1_791_288_000_000L

    @Test
    fun dayLabel_today() {
        assertEquals("Today", messageDayLabel("2026-10-06T09:00:00", now, zone))
    }

    @Test
    fun dayLabel_yesterday() {
        assertEquals("Yesterday", messageDayLabel("2026-10-05T23:59:00", now, zone))
    }

    @Test
    fun dayLabel_older_alwaysYearQualified() {
        assertEquals("03 Oct 2026", messageDayLabel("2026-10-03T10:00:00", now, zone))
        assertEquals("31 Dec 2025", messageDayLabel("2025-12-31", now, zone))
    }

    @Test
    fun dayLabel_blankOrGarbage_isNull() {
        assertNull(messageDayLabel(null, now, zone))
        assertNull(messageDayLabel("", now, zone))
        assertNull(messageDayLabel("  ", now, zone))
        assertNull(messageDayLabel("not-a-date", now, zone))
    }

    @Test
    fun dayLabel_offsetInput_convertsToZone() {
        // 00:30+02:00 is 22:30 UTC the previous day.
        assertEquals(
            "Yesterday",
            messageDayLabel("2026-10-06T00:30:00+02:00", now, zone),
        )
    }

    @Test
    fun mapMessageRow_passesRawTimestampThrough() {
        val entity = MessageEntity(
            messageId = "m-9",
            conversationId = "conv-9",
            sequenceNumber = 4L,
            direction = MessageDirection.IN,
            senderDeviceId = "dev-b",
            recipientDeviceId = "dev-a",
            envelopeType = "RATCHET",
            ciphertext = null,
            plaintextSealed = null,
            sendState = null,
            requestId = null,
            serverTimestamp = "2026-10-03T10:00:00",
            createdAt = 1000L,
        )
        val mapped = mapMessageRow(entity, "bob") { _, _ -> "t" }
        assertEquals("2026-10-03T10:00:00", mapped.serverTimestamp)
        assertEquals("2026-10-03T10:00:00", mapped.meta)
    }

    // ---- Bubbles ----

    @Test
    fun bubbles_announceOwnershipTextAndTime() {
        render(
            messages = listOf(
                row(messageId = "m-1", text = "hello-e"),
                row(
                    messageId = "m-2",
                    isOutbound = true,
                    senderLabel = "You",
                    text = "hi-e",
                ),
            )
        )

        composeTestRule.onNodeWithText("hello-e").assertIsDisplayed()
        composeTestRule.onNodeWithText("hi-e").assertIsDisplayed()
        composeTestRule
            .onNodeWithContentDescription("bob, hello-e, not-a-date-e")
            .assertIsDisplayed()
        composeTestRule
            .onNodeWithContentDescription("You, hi-e, not-a-date-e")
            .assertIsDisplayed()
    }

    @Test
    fun pending_showsSendingMarker_andNoTimestamp() {
        render(
            messages = listOf(
                row(
                    messageId = "m-1",
                    isOutbound = true,
                    senderLabel = "You",
                    text = "out-e",
                    serverTimestamp = "",
                ),
            )
        )

        composeTestRule.onNodeWithText("Sending…").assertIsDisplayed()
    }

    @Test
    fun acceptedButUnstamped_showsSentFallback() {
        render(
            messages = listOf(
                row(
                    messageId = "m-1",
                    isOutbound = true,
                    senderLabel = "You",
                    text = "out-e",
                    serverTimestamp = "",
                ).copy(meta = "2026-10-03T10:00:00"),
            )
        )

        composeTestRule.onNodeWithText("Sent").assertIsDisplayed()
    }

    @Test
    fun unparseableTimestamp_echoesRaw() {
        render(messages = listOf(row(serverTimestamp = "raw-ts-e")))

        composeTestRule.onNodeWithText("raw-ts-e").assertIsDisplayed()
    }

    @Test
    fun unknownSender_showsSenderLine() {
        render(
            peerLabel = "bob",
            messages = listOf(
                row(senderLabel = "Unknown sender", text = "strange-e"),
            ),
        )

        // Sender adds information beyond the peer header: visible.
        // The sender line lives under a merging bubble parent, so the
        // tag resolves in the unmerged tree.
        composeTestRule.onNodeWithText("Unknown sender").assertIsDisplayed()
        composeTestRule.onNodeWithTag("MessageSenderLabel", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun peerSender_hidesRedundantSenderLine() {
        render(
            peerLabel = "bob",
            messages = listOf(row(senderLabel = "bob", text = "hello-e")),
        )

        // The header already names the 1:1 peer: no redundant sender
        // line. Readers still get the sender through the bubble
        // description (asserted in bubbles_announceOwnershipTextAndTime).
        composeTestRule.onNodeWithText("hello-e").assertIsDisplayed()
        composeTestRule.onNodeWithTag("MessageSenderLabel", useUnmergedTree = true)
            .assertDoesNotExist()
    }

    // ---- Grouping + separators ----

    private fun isoTodayAt(hour: Int): String =
        LocalDate.now().atTime(hour, 0).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)

    private fun isoYesterdayAt(hour: Int): String =
        LocalDate.now().minusDays(1).atTime(hour, 0)
            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)

    @Test
    fun separators_splitDays() {
        render(
            messages = listOf(
                row(messageId = "m-1", text = "old-e", serverTimestamp = isoYesterdayAt(10)),
                row(messageId = "m-2", text = "new-e", serverTimestamp = isoTodayAt(10)),
            )
        )

        composeTestRule.onNodeWithText("old-e").assertIsDisplayed()
        composeTestRule.onNodeWithText("new-e").assertIsDisplayed()
        // Separators carry the day as both text and description; the
        // bubble time captions reuse the same words, so the exact
        // description singles out the separator nodes.
        composeTestRule.onNodeWithContentDescription("Yesterday")
            .assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("Today")
            .assertIsDisplayed()
    }

    @Test
    fun grouping_sameDirectionSameDay_showsOneCaption() {
        val first = isoTodayAt(10)
        val second = isoTodayAt(11)
        render(
            messages = listOf(
                row(
                    messageId = "m-1",
                    isOutbound = true,
                    senderLabel = "You",
                    text = "one-e",
                    serverTimestamp = first,
                ),
                row(
                    messageId = "m-2",
                    isOutbound = true,
                    senderLabel = "You",
                    text = "two-e",
                    serverTimestamp = second,
                ),
            )
        )

        // Only the group-last caption renders.
        composeTestRule.onNodeWithText(formatServerTimestamp(second))
            .assertIsDisplayed()
        composeTestRule.onNodeWithText(formatServerTimestamp(first))
            .assertDoesNotExist()
        // Both bubbles still render.
        composeTestRule.onNodeWithText("one-e").assertIsDisplayed()
        composeTestRule.onNodeWithText("two-e").assertIsDisplayed()
    }

    @Test
    fun directionChange_breaksGroup() {
        val first = isoTodayAt(10)
        val second = isoTodayAt(11)
        render(
            messages = listOf(
                row(
                    messageId = "m-1",
                    text = "in-e",
                    serverTimestamp = first,
                ),
                row(
                    messageId = "m-2",
                    isOutbound = true,
                    senderLabel = "You",
                    text = "out-e",
                    serverTimestamp = second,
                ),
            )
        )

        composeTestRule.onNodeWithText(formatServerTimestamp(first))
            .assertIsDisplayed()
        composeTestRule.onNodeWithText(formatServerTimestamp(second))
            .assertIsDisplayed()
    }

    // ---- States ----

    @Test
    fun empty_showsIntentionalEmptyState() {
        render(messages = emptyList())

        composeTestRule.onNodeWithText("No messages yet.").assertIsDisplayed()
        composeTestRule.onNodeWithText("Messages you send and receive will appear here.")
            .assertIsDisplayed()
    }

    @Test
    fun loading_showsSkeleton_andNoRows() {
        render(messages = null)

        composeTestRule.onNodeWithTag("DetailLoading").assertIsDisplayed()
        composeTestRule.onNodeWithText("No messages yet.").assertDoesNotExist()
    }

    @Test
    fun error_rendersCard_withWorkingRetry() {
        var retried = false
        render(messages = null, loadError = "Could not load messages.") {
            retried = true
        }

        composeTestRule.onNodeWithText("Could not load messages.")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Retry").performClick()
        assertTrue(retried)
    }

    @Test
    fun header_showsPeer_andSync() {
        var synced = false
        render(
            peerLabel = "bob",
            onSync = { synced = true },
        )

        composeTestRule.onNodeWithText("bob").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sync").performClick()
        assertTrue(synced)
    }

    @Test
    fun syncing_showsProgress_andSyncErrorCard() {
        render(
            messages = emptyList(),
            syncing = true,
            syncError = "Sync had partial failures.",
        )

        composeTestRule.onNodeWithText("Syncing…").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sync had partial failures.")
            .assertIsDisplayed()
    }

    @Test
    fun composerSlot_rendersAsFooter() {
        render(
            messages = listOf(row()),
            composer = {
                androidx.compose.material3.Text("composer-sentinel-e")
            },
        )

        composeTestRule.onNodeWithText("composer-sentinel-e").assertIsDisplayed()
        composeTestRule.onNodeWithTag("ChatDetailList").assertIsDisplayed()
    }

    @Test
    fun manyRows_allRender_inOrder() {
        render(
            messages = (1..30).map { i ->
                row(
                    messageId = "m-$i",
                    text = "bulk-e-$i",
                    sequenceNumber = i.toLong(),
                    isOutbound = i % 2 == 0,
                    senderLabel = if (i % 2 == 0) "You" else "bob",
                )
            }
        )

        composeTestRule.onNodeWithText("bulk-e-30").assertIsDisplayed()
        // The list opens at the latest message: row 1 is disposed until
        // scrolled to through the list itself.
        composeTestRule.onNodeWithTag("ChatDetailList").performScrollToIndex(0)
        composeTestRule.onNodeWithText("bulk-e-1").assertIsDisplayed()
    }

    // ---- Composer guards (redesign preserved behavior) ----

    private fun renderComposer(
        draft: String,
        selectedDeviceId: String?,
        sending: Boolean = false,
    ) {
        composeTestRule.setContent {
            SamvaadTheme {
                ComposerUi(
                    username = "bob",
                    onUsernameChange = {},
                    draft = draft,
                    onDraftChange = {},
                    devices = null,
                    findingDevices = false,
                    directoryError = null,
                    selectedDeviceId = selectedDeviceId,
                    onFindDevices = {},
                    onSelectDevice = {},
                    sending = sending,
                    sendError = null,
                    onSend = {},
                )
            }
        }
    }

    @Test
    fun composer_sendDisabled_withoutDeviceOrDraft() {
        renderComposer(draft = "hi-e", selectedDeviceId = null)
        composeTestRule.onNodeWithText("Send").assertIsNotEnabled()
    }

    @Test
    fun composer_sendEnabled_withDeviceAndDraft() {
        renderComposer(draft = "hi-e", selectedDeviceId = "dev-1")
        composeTestRule.onNodeWithText("Send").assertIsEnabled()
    }

    @Test
    fun composer_sending_disablesSend() {
        renderComposer(draft = "hi-e", selectedDeviceId = "dev-1", sending = true)
        composeTestRule.onNodeWithText("Sending…").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sending…").assertIsNotEnabled()
    }

    // ---- Integrated shell flow (real loader path) ----

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = key
    }

    private class FakeE2ee : E2eeDeviceApi {
        override suspend fun enroll(
            session: AuthSession,
            serverAddress: String,
            request: EnrollRequest,
        ): EnrollResult = throw AssertionError("no enrollment in this slice")

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ): Unit = throw AssertionError("no provisioning in this slice")

        override suspend fun listDevices(
            session: AuthSession,
            serverAddress: String,
        ): DeviceList = throw AssertionError("no device list in this slice")

        override suspend fun approveDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
        ): DeviceRecord = throw AssertionError("no approval in this slice")

        override suspend fun bindDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            recoveryCode: String,
        ): DeviceRecord = throw AssertionError("no bind in this slice")

        override suspend fun beginAttach(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
        ): AttachBegin = AttachBegin.AlreadyBound(
            DeviceRecord(
                deviceId = deviceId,
                registrationId = 4242,
                signalDeviceId = 1,
                deviceIdentityPublicKey = "aWRlbnRpdHk=",
                signedPrekeyId = 1,
                deviceRole = "PRIMARY",
                status = "ACTIVE",
                availablePrekeys = 100,
            )
        )

        override suspend fun completeAttach(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            challengeId: String,
            proofBase64: String,
        ): DeviceRecord = throw AssertionError("no attach in this slice")

        override suspend fun recoverEnroll(
            session: AuthSession,
            serverAddress: String,
            recoveryCode: String,
            request: EnrollRequest,
        ): DeviceRecord = throw AssertionError("no recovery in this slice")

        override suspend fun listRecipientDevices(
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): List<RecipientDeviceRecord> = throw AssertionError("no directory in this slice")

        override suspend fun claimOneTimePrekey(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            requestId: UUID,
        ): ClaimedDeviceBundle = throw AssertionError("no claim in this slice")

        override suspend fun submitMessage(
            session: AuthSession,
            serverAddress: String,
            requestId: UUID,
            envelopes: List<MessageEnvelopeSubmit>,
        ): SubmitMessageResult = throw AssertionError("no submit in this slice")

        override suspend fun fetchMailbox(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<MailboxItem> = throw AssertionError("no mailbox in this slice")

        override suspend fun ackMailbox(
            session: AuthSession,
            serverAddress: String,
            messageIds: List<UUID>,
        ): Int = throw AssertionError("no ack in this slice")

        override suspend fun fetchHistory(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<HistoryItem> = throw AssertionError("no history in this slice")

        override suspend fun getSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
        ): SyncCursor = throw AssertionError("no cursor in this slice")

        override suspend fun advanceSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): SyncCursor = throw AssertionError("no cursor in this slice")

        override suspend fun listConversations(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<String> = throw AssertionError("no conversations in this slice")

        override suspend fun uploadSyncBatch(
            session: AuthSession,
            serverAddress: String,
            request: SyncUploadRequest,
        ): SyncUploadResult = throw AssertionError("no history sync in this slice")

        override suspend fun fetchSyncBatch(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<SyncBatchItem> = throw AssertionError("no history sync in this slice")

        override suspend fun ackSync(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): SyncAckResult = throw AssertionError("no history sync in this slice")
    }

    private class FakeFriends : FriendsApi {
        override suspend fun lookupUser(
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): FriendEntry = throw AssertionError("no lookup in this slice")

        override suspend fun sendRequest(
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): FriendRequestRecord = throw AssertionError("no friend requests in this slice")

        override suspend fun listIncoming(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendRequestRecord> = emptyList()

        override suspend fun listOutgoing(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendRequestRecord> = emptyList()

        override suspend fun acceptRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord = throw AssertionError("no friend requests in this slice")

        override suspend fun rejectRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord = throw AssertionError("no friend requests in this slice")

        override suspend fun cancelRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord = throw AssertionError("no friend requests in this slice")

        override suspend fun listFriends(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendEntry> = emptyList()
    }

    private lateinit var context: Context
    private lateinit var keys: EphemeralKeys

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, FileSessionMetadataStore.SUBDIR).deleteRecursively()
        File(MessageDatabase.file(context).parent!!).deleteRecursively()
        keys = EphemeralKeys()
    }

    private fun sealLocalDevice() {
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 1)
        val kyber = adapter.generateKyberPrekey(identity, 1)
        val otpks = (1..100).map { adapter.generateOneTimePrekey(5000 + it) }
        val vault = AndroidCryptoVault(context, keys)
        vault.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        vault.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        vault.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            vault.seal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY, adapter.exportRecord(it.privateHandle))
        }
        FileDeviceMetadataStore(context).writeAdopted(
            AdoptedDevice(
                deviceId = "11111111-1111-1111-1111-111111111111",
                signalDeviceId = 1,
                registrationId = 4242,
                identityPublicKeyB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey),
                signedPrekeyId = signed.prekeyId,
                kyberPrekeyId = kyber.prekeyId,
                otpkHighWaterMark = otpks.maxOf { it.prekeyId },
                roleHint = "PRIMARY",
                statusHint = "ACTIVE",
                identityHandleId = identity.privateHandle.id.toString(),
                signedHandleId = signed.privateHandle.id.toString(),
                kyberHandleId = kyber.privateHandle.id.toString(),
                otpkHandleIds = otpks.map { it.privateHandle.id.toString() },
                codesAcknowledged = true,
            )
        )
    }

    private fun seedInbound(
        conversationId: String,
        messageId: String,
        sequenceNumber: Long,
        text: String,
    ) {
        val db = MessageDatabase.open(context)
        try {
            kotlinx.coroutines.runBlocking {
                val dao = db.messageDao()
                dao.upsertConversation(ConversationEntity(conversationId))
                dao.insertIgnore(
                    MessageEntity(
                        messageId = messageId,
                        conversationId = conversationId,
                        sequenceNumber = sequenceNumber,
                        direction = MessageDirection.IN,
                        senderDeviceId = "bob-dev-1",
                        recipientDeviceId = "11111111-1111-1111-1111-111111111111",
                        envelopeType = "RATCHET",
                        ciphertext = "cipher".toByteArray(),
                        plaintextSealed = MessageContentSealer(keys).seal(messageId, text.toByteArray()),
                        sendState = null,
                        acked = true,
                        requestId = null,
                        serverTimestamp = "2026-10-03T10:00:00",
                        createdAt = 1000L,
                    )
                )
            }
        } finally {
            db.close()
        }
        FileSessionMetadataStore(context).write(
            SignalSessionEntry(
                remoteDeviceId = "bob-dev-1",
                remoteUsername = "bob",
                remoteSignalDeviceId = 2,
                remoteRegistrationId = 7001,
                remoteIdentityPublicKeyB64 = "Ym9iLWtleQ==",
                establishedVia = EstablishedVia.WITH_OTPK,
                localIdentityHandleId = "00000000-0000-0000-0000-000000000000",
                createdAt = 0L,
                updatedAt = 0L,
            )
        )
    }

    private fun launchShell() {
        val coordinator = EnrollmentCoordinator(
            api = FakeE2ee(),
            metadata = FileDeviceMetadataStore(context),
            adapter = AndroidSignalAdapter(),
            vault = AndroidCryptoVault(context, keys),
        )
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadAppShell(
                    identifier = "alice",
                    session = session,
                    serverAddress = "https://example.test:8080",
                    coordinator = coordinator,
                    deviceApi = FakeE2ee(),
                    wrappingKeys = keys,
                    friendsApi = FakeFriends(),
                )
            }
        }
    }

    private fun waitFor(text: String, substring: Boolean = false) {
        composeTestRule.waitUntil(60_000) {
            try {
                composeTestRule.onNodeWithText(text, substring = substring)
                    .fetchSemanticsNode()
                true
            } catch (_: AssertionError) {
                false
            }
        }
    }

    @Test
    fun shell_detail_rendersBubblesThroughNewScreen_andBackReturns() {
        sealLocalDevice()
        seedInbound("conv-1", "m-1", 1L, "first-bubble-e")
        seedInbound("conv-1", "m-2", 2L, "second-bubble-e")
        launchShell()

        // Chats list (new Slice C UI) through the real loader.
        waitFor("bob")
        composeTestRule.onNodeWithText("bob").performScrollTo()
        composeTestRule.onNodeWithText("bob").performClick()
        // New detail screen: shell Back, peer header, latest bubble.
        // Multi-row rendering and list scrolling are covered by the
        // direct manyRows test; here the latest bubble plus Back plus
        // the return trip prove the new screen mounts through the
        // shell with real loader data.
        waitFor("Back")
        composeTestRule.onNodeWithText("second-bubble-e").assertIsDisplayed()

        composeTestRule.onNodeWithText("Back").performClick()
        waitFor("Conversations")
    }
}
