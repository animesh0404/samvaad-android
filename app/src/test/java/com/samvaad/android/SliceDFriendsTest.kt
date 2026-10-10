package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
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
import com.samvaad.android.friends.FriendException
import com.samvaad.android.friends.FriendRequestRecord
import com.samvaad.android.friends.FriendsApi
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.SignalSessionEntry
import com.samvaad.android.ui.theme.SamvaadTheme
import com.samvaad.android.ui.util.formatServerTimestamp
import java.io.File
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice D Friends tests (host-side via Robolectric).
 *
 * Direct [FriendsSection] renders cover rows/states/errors with
 * fabricated models (no network); HomeScreen-integrated flows cover
 * cancel (success + failure) and Message → conversation resolution
 * against the real loader path with file-backed Room. Typed strings
 * here are fake sentinels.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceDFriendsTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun incomingRequest(
        requestId: String = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        senderUsername: String = "bob",
        createdAt: String? = "2026-10-05T10:00:00",
    ) = FriendRequestRecord(
        requestId = requestId,
        senderUserId = "22222222-2222-2222-2222-222222222222",
        senderUsername = senderUsername,
        recipientUserId = "11111111-1111-1111-1111-111111111111",
        recipientUsername = "alice",
        status = "PENDING",
        createdAt = createdAt,
        respondedAt = null,
    )

    private fun outgoingRequest(
        requestId: String = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        recipientUsername: String = "carol",
        createdAt: String? = "2026-10-05T11:00:00",
    ) = FriendRequestRecord(
        requestId = requestId,
        senderUserId = "11111111-1111-1111-1111-111111111111",
        senderUsername = "alice",
        recipientUserId = "33333333-3333-3333-3333-333333333333",
        recipientUsername = recipientUsername,
        status = "PENDING",
        createdAt = createdAt,
        respondedAt = null,
    )

    private fun friendOf(username: String, userId: String = "$username-id") =
        FriendEntry(userId = userId, username = username)

    private fun render(
        friends: List<FriendEntry>? = emptyList(),
        incoming: List<FriendRequestRecord>? = emptyList(),
        outgoing: List<FriendRequestRecord>? = emptyList(),
        loadingRoster: Boolean = false,
        rosterError: String? = null,
        respondingRequestId: String? = null,
        respondError: String? = null,
        cancellingRequestId: String? = null,
        cancelError: String? = null,
        resolvingMessageUsername: String? = null,
        messageHint: String? = null,
        onAccept: (String) -> Unit = {},
        onReject: (String) -> Unit = {},
        onCancel: (String) -> Unit = {},
        onMessage: (String) -> Unit = {},
        onRefresh: () -> Unit = {},
    ) {
        composeTestRule.setContent {
            SamvaadTheme {
                FriendsSection(
                    friends = friends,
                    incoming = incoming,
                    outgoing = outgoing,
                    loadingRoster = loadingRoster,
                    rosterError = rosterError,
                    onRefreshRoster = onRefresh,
                    addUsername = "",
                    onAddUsernameChange = {},
                    sendingRequest = false,
                    addFriendError = null,
                    addFriendSuccess = null,
                    onSendRequest = {},
                    respondingRequestId = respondingRequestId,
                    respondError = respondError,
                    onAccept = onAccept,
                    onReject = onReject,
                    cancellingRequestId = cancellingRequestId,
                    cancelError = cancelError,
                    onCancel = onCancel,
                    resolvingMessageUsername = resolvingMessageUsername,
                    messageHint = messageHint,
                    onMessage = onMessage,
                )
            }
        }
    }

    // ---- Incoming ----

    @Test
    fun incoming_rendersUsernameTimestampAndActions() {
        val ts = "2026-10-05T10:00:00"
        render(incoming = listOf(incomingRequest(createdAt = ts)))

        composeTestRule.onNodeWithText("Friend requests").assertIsDisplayed()
        composeTestRule.onNodeWithText("Request from bob").assertIsDisplayed()
        composeTestRule.onNodeWithText("Requested ${formatServerTimestamp(ts)}")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Accept").assertIsDisplayed()
        composeTestRule.onNodeWithText("Reject").assertIsDisplayed()
    }

    @Test
    fun incoming_missingTimestamp_hidesRequestedLine() {
        render(incoming = listOf(incomingRequest(createdAt = null)))

        composeTestRule.onNodeWithText("Request from bob").assertIsDisplayed()
        composeTestRule.onNodeWithText("Requested", substring = true)
            .assertDoesNotExist()
    }

    @Test
    fun incoming_acceptAndReject_reportRequestId() {
        val accepted = mutableListOf<String>()
        val rejected = mutableListOf<String>()
        render(
            incoming = listOf(incomingRequest()),
            onAccept = { accepted.add(it) },
            onReject = { rejected.add(it) },
        )

        composeTestRule.onNodeWithText("Accept").performScrollTo().performClick()
        composeTestRule.onNodeWithText("Reject").performScrollTo().performClick()
        assertEquals(
            listOf("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            accepted,
        )
        assertEquals(
            listOf("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            rejected,
        )
    }

    @Test
    fun incoming_busyRow_showsAccepting_andDisablesActions() {
        render(
            incoming = listOf(incomingRequest()),
            respondingRequestId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )

        composeTestRule.onNodeWithText("Accepting…").assertIsDisplayed()
        composeTestRule.onNodeWithText("Accepting…").assertIsNotEnabled()
        composeTestRule.onNodeWithText("Reject").assertIsNotEnabled()
    }

    @Test
    fun incoming_idleActions_areEnabled() {
        render(incoming = listOf(incomingRequest()))

        composeTestRule.onNodeWithText("Accept").assertIsEnabled()
        composeTestRule.onNodeWithText("Reject").assertIsEnabled()
    }

    // ---- Outgoing ----

    @Test
    fun outgoing_rendersPendingCancelAndTimestamp() {
        val ts = "2026-10-05T11:00:00"
        render(outgoing = listOf(outgoingRequest(createdAt = ts)))

        composeTestRule.onNodeWithText("Outgoing requests").assertIsDisplayed()
        composeTestRule.onNodeWithText("carol").assertIsDisplayed()
        composeTestRule
            .onNodeWithText("Request pending", substring = true)
            .assertIsDisplayed()
        composeTestRule
            .onNodeWithText(formatServerTimestamp(ts), substring = true)
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Cancel").assertIsDisplayed()
    }

    @Test
    fun outgoing_cancel_reportsRequestId() {
        val cancelled = mutableListOf<String>()
        render(
            outgoing = listOf(outgoingRequest()),
            onCancel = { cancelled.add(it) },
        )

        composeTestRule.onNodeWithText("Cancel").performScrollTo().performClick()
        assertEquals(
            listOf("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            cancelled,
        )
    }

    @Test
    fun outgoing_cancelling_showsProgress_andDisablesCancel() {
        render(
            outgoing = listOf(outgoingRequest()),
            cancellingRequestId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        )

        composeTestRule.onNodeWithText("Cancelling…").assertIsDisplayed()
        composeTestRule.onNodeWithText("Cancelling…").assertIsNotEnabled()
    }

    // ---- Accepted ----

    @Test
    fun accepted_rendersFriendWithMessageCta() {
        render(friends = listOf(friendOf("dave")))

        composeTestRule.onNodeWithText("Accepted friends").assertIsDisplayed()
        composeTestRule.onNodeWithText("dave").assertIsDisplayed()
        composeTestRule.onNodeWithText("Friend").assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("dave, friend")
            .assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("Message dave")
            .assertIsDisplayed()
            .assertIsEnabled()
    }

    @Test
    fun accepted_messageTap_reportsUsername() {
        var messaged: String? = null
        render(
            friends = listOf(friendOf("dave")),
            onMessage = { messaged = it },
        )

        composeTestRule.onNodeWithContentDescription("Message dave")
            .performScrollTo()
            .performClick()
        assertEquals("dave", messaged)
    }

    @Test
    fun accepted_resolving_showsOpening_andDisablesMessage() {
        render(
            friends = listOf(friendOf("dave")),
            resolvingMessageUsername = "dave",
        )

        composeTestRule.onNodeWithText("Opening…").assertIsDisplayed()
        composeTestRule.onNodeWithText("Opening…").assertIsNotEnabled()
    }

    // ---- Empty / loading / errors ----

    @Test
    fun empty_hidesRequestSections_andShowsFriendsEmptyState() {
        render()

        composeTestRule.onNodeWithText("No friends yet. Add someone above.")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Friend requests").assertDoesNotExist()
        composeTestRule.onNodeWithText("Outgoing requests").assertDoesNotExist()
        composeTestRule.onNodeWithText("Accepted friends").assertDoesNotExist()
        // Add-friend affordance stays (existing action, existing strings).
        composeTestRule.onNodeWithText("New friend username").assertIsDisplayed()
        composeTestRule.onNodeWithText("Add friend").assertIsDisplayed()
        composeTestRule.onNodeWithText("Refresh friends").assertIsDisplayed()
    }

    @Test
    fun loading_showsSkeleton_andNoContent() {
        render(loadingRoster = true)

        composeTestRule.onNodeWithTag("FriendsLoading").assertIsDisplayed()
        composeTestRule.onNodeWithText("No friends yet. Add someone above.")
            .assertDoesNotExist()
    }

    @Test
    fun rosterError_rendersCard_andRefreshRetries() {
        var refreshed = false
        render(
            friends = null,
            rosterError = "Could not load friends. Check the connection and try again.",
            onRefresh = { refreshed = true },
        )

        composeTestRule
            .onNodeWithText(
                "Could not load friends. Check the connection and try again.",
            )
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Refresh friends").performScrollTo()
            .performClick()
        assertTrue(refreshed)
    }

    @Test
    fun operationErrors_renderWithoutHidingLists() {
        render(
            friends = listOf(friendOf("dave")),
            respondError = "That request is no longer waiting.",
            cancelError = "Could not cancel the request. Check the connection and try again.",
            messageHint = "No conversation with dave yet.",
        )

        composeTestRule.onNodeWithText("That request is no longer waiting.")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule
            .onNodeWithText(
                "Could not cancel the request. Check the connection and try again.",
            )
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("No conversation with dave yet.")
            .performScrollTo()
            .assertIsDisplayed()
        // Lists stay visible behind operation errors.
        composeTestRule.onNodeWithText("dave").assertIsDisplayed()
    }

    // ---- Accessibility semantics ----

    @Test
    fun semantics_requestRowsAndActions_announceState() {
        // Accepted-row semantics live in
        // accepted_rendersFriendWithMessageCta: a full three-section
        // list disposes off-viewport rows, so cross-section description
        // lookups are inherently order- and viewport-dependent.
        render(
            incoming = listOf(incomingRequest()),
            outgoing = listOf(outgoingRequest()),
        )

        composeTestRule
            .onNodeWithContentDescription("bob, incoming friend request")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule
            .onNodeWithContentDescription("Accept friend request from bob")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule
            .onNodeWithContentDescription("Reject friend request from bob")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule
            .onNodeWithContentDescription(
                "carol, outgoing friend request, pending",
            )
            .performScrollTo()
            .assertIsDisplayed()
    }

    // ---- Integrated flows (HomeScreen, real loader path) ----

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
        ): AttachBegin = throw AssertionError("no attach in this slice")

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
        ): List<String> = throw AssertionError("no conversation list in this slice")

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
        var friends: List<FriendEntry> = emptyList()
        var incoming: List<FriendRequestRecord> = emptyList()
        var outgoing: List<FriendRequestRecord> = emptyList()
        val cancelled = mutableListOf<String>()
        var cancelHandler: (String) -> FriendRequestRecord = { requestId ->
            FriendRequestRecord(
                requestId = requestId,
                senderUserId = "11111111-1111-1111-1111-111111111111",
                senderUsername = "alice",
                recipientUserId = "33333333-3333-3333-3333-333333333333",
                recipientUsername = "carol",
                status = "CANCELLED",
                createdAt = null,
                respondedAt = null,
            )
        }

        override suspend fun lookupUser(
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): FriendEntry = throw AssertionError("no lookup in this slice")

        override suspend fun sendRequest(
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): FriendRequestRecord = throw AssertionError("no send in this slice")

        override suspend fun listIncoming(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendRequestRecord> = incoming

        override suspend fun listOutgoing(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendRequestRecord> = outgoing

        override suspend fun acceptRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord = throw AssertionError("no accept in this slice")

        override suspend fun rejectRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord = throw AssertionError("no reject in this slice")

        override suspend fun cancelRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord {
            cancelled.add(requestId)
            val done = cancelHandler(requestId)
            outgoing = outgoing.filterNot { it.requestId == requestId }
            return done
        }

        override suspend fun listFriends(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendEntry> = friends
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

    private fun writeHandleLessAdopted() {
        FileDeviceMetadataStore(context).writeAdopted(
            AdoptedDevice(
                deviceId = "11111111-1111-1111-1111-111111111111",
                signalDeviceId = 1,
                registrationId = 5150,
                identityPublicKeyB64 = "c2VydmVyLWtleQ==",
                signedPrekeyId = 9,
                kyberPrekeyId = 11,
                otpkHighWaterMark = 0,
                roleHint = "PRIMARY",
                statusHint = "ACTIVE",
                identityHandleId = null,
                signedHandleId = null,
                kyberHandleId = null,
                otpkHandleIds = emptyList(),
                codesAcknowledged = true,
            )
        )
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
        senderDeviceId: String,
        senderUsername: String,
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
                        senderDeviceId = senderDeviceId,
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
                remoteDeviceId = senderDeviceId,
                remoteUsername = senderUsername,
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

    private fun launchHome(friendsApi: FakeFriends) {
        val coordinator = EnrollmentCoordinator(
            api = FakeE2ee(),
            metadata = FileDeviceMetadataStore(context),
            adapter = AndroidSignalAdapter(),
            vault = AndroidCryptoVault(context, keys),
        )
        composeTestRule.setContent {
            SamvaadTheme {
                HomeScreen(
                    identifier = "alice",
                    session = session,
                    serverAddress = "https://example.test:8080",
                    coordinator = coordinator,
                    deviceApi = FakeE2ee(),
                    wrappingKeys = keys,
                    friendsApi = friendsApi,
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

    private fun waitUntilGone(text: String) {
        composeTestRule.waitUntil(60_000) {
            try {
                composeTestRule.onNodeWithText(text).fetchSemanticsNode()
                false
            } catch (_: AssertionError) {
                true
            }
        }
    }

    @Test
    fun cancel_success_callsApiAndRemovesRow() {
        val fake = FakeFriends().apply {
            outgoing = listOf(outgoingRequest())
        }
        writeHandleLessAdopted()
        launchHome(fake)

        waitFor("carol")
        composeTestRule.onNodeWithContentDescription("Cancel friend request to carol")
            .performScrollTo()
            .performClick()
        waitUntilGone("carol")
        assertEquals(
            listOf("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            fake.cancelled,
        )
    }

    @Test
    fun cancel_failure_retainsRowAndShowsError() {
        val fake = FakeFriends().apply {
            outgoing = listOf(outgoingRequest())
            cancelHandler = { throw FriendException.Transport() }
        }
        writeHandleLessAdopted()
        launchHome(fake)

        waitFor("carol")
        composeTestRule.onNodeWithContentDescription("Cancel friend request to carol")
            .performScrollTo()
            .performClick()
        waitFor("Could not cancel the request. Check the connection and try again.")
        // The request is retained: Cancel stays available for retry.
        composeTestRule.onNodeWithContentDescription("Cancel friend request to carol")
            .assertIsDisplayed()
            .assertIsEnabled()
        assertEquals(
            listOf("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            fake.cancelled,
        )
    }

    @Test
    fun message_resolvesToExistingConversation_andOpensDetail() {
        sealLocalDevice()
        seedInbound("conv-77", "m-1", 1L, "bob-dev-1", "bob", "detail-msg-d")
        val fake = FakeFriends().apply {
            friends = listOf(friendOf("bob", "22222222-2222-2222-2222-222222222222"))
        }
        launchHome(fake)

        waitFor("Accepted friends")
        composeTestRule.onNodeWithContentDescription("Message bob")
            .performScrollTo()
            .performClick()
        // Full-mode inline detail: Back affordance plus the message row.
        waitFor("Back")
        composeTestRule.onNodeWithText("detail-msg-d").performScrollTo()
        composeTestRule.onNodeWithText("detail-msg-d").assertIsDisplayed()
    }

    @Test
    fun message_withoutConversation_showsHintAndStaysPut() {
        val fake = FakeFriends().apply {
            friends = listOf(friendOf("erin", "44444444-4444-4444-4444-444444444444"))
        }
        writeHandleLessAdopted()
        launchHome(fake)

        waitFor("Accepted friends")
        composeTestRule.onNodeWithContentDescription("Message erin")
            .performScrollTo()
            .performClick()
        waitFor("No conversation with erin yet.", substring = true)
        // No navigation happened: the Friends destination is intact.
        composeTestRule.onNodeWithText("Accepted friends").assertIsDisplayed()
    }
    @Test
    fun columnContainer_rendersSameRows_asLazySection() {
        // The Full-mode non-lazy container must render the same rows as
        // the lazy destination (legacy strings preserved verbatim).
        composeTestRule.setContent {
            SamvaadTheme {
                FriendsColumn(
                    friends = emptyList(),
                    incoming = listOf(incomingRequest()),
                    outgoing = emptyList(),
                    loadingRoster = false,
                    rosterError = null,
                    onRefreshRoster = {},
                    addUsername = "",
                    onAddUsernameChange = {},
                    sendingRequest = false,
                    addFriendError = null,
                    addFriendSuccess = null,
                    onSendRequest = {},
                    respondingRequestId = null,
                    respondError = null,
                    onAccept = {},
                    onReject = {},
                    cancellingRequestId = null,
                    cancelError = null,
                    onCancel = {},
                    resolvingMessageUsername = null,
                    messageHint = null,
                    onMessage = {},
                )
            }
        }
        composeTestRule.onNodeWithText("Request from bob").assertIsDisplayed()
        composeTestRule.onNodeWithText("Accept").assertIsDisplayed()
        composeTestRule.onNodeWithText("Reject").assertIsDisplayed()
    }
}
