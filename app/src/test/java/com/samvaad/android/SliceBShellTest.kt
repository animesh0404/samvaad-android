package com.samvaad.android

import android.content.Context
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
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
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.enroll.SyncCursor
import com.samvaad.android.friends.FriendEntry
import com.samvaad.android.friends.FriendRequestRecord
import com.samvaad.android.friends.FriendsApi
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.session.SignalSessionEntry
import com.samvaad.android.ui.shell.SamvaadAppShell
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.File
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice B shell/navigation tests (host-side via Robolectric).
 *
 * The shell mounts one HomeScreen per destination with the existing
 * fake seams; no network is touched. Typed strings are fake sentinels.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceBShellTest {

    @get:Rule
    val composeTestRule = createComposeRule()

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
            envelopes: List<com.samvaad.android.enroll.MessageEnvelopeSubmit>,
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
            request: com.samvaad.android.enroll.SyncUploadRequest,
        ): com.samvaad.android.enroll.SyncUploadResult =
            throw AssertionError("no history sync in this slice")

        override suspend fun fetchSyncBatch(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<com.samvaad.android.enroll.SyncBatchItem> =
            throw AssertionError("no history sync in this slice")

        override suspend fun ackSync(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): com.samvaad.android.enroll.SyncAckResult =
            throw AssertionError("no history sync in this slice")
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

    private class FakeAuthApi : AuthApi {
        override suspend fun login(request: LoginRequest): AuthSession =
            throw AssertionError("no login in this slice")

        override suspend fun refresh(
            serverAddress: String,
            refreshToken: String,
        ): RefreshedSession = throw AssertionError("no refresh in this slice")

        override suspend fun logout(serverAddress: String, accessToken: String) = Unit
    }

    private lateinit var context: Context
    private lateinit var api: FakeE2ee
    private lateinit var keys: EphemeralKeys
    private lateinit var friends: FakeFriends

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
        File(context.noBackupFilesDir, FileSessionStore.SUBDIR).deleteRecursively()
        File(MessageDatabase.file(context).parent!!).deleteRecursively()
        api = FakeE2ee()
        keys = EphemeralKeys()
        friends = FakeFriends()
    }

    private fun launchShell() {
        val coordinator = EnrollmentCoordinator(
            api = api,
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
                    deviceApi = api,
                    wrappingKeys = keys,
                    friendsApi = friends,
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

    private fun openTab(label: String) {
        // Tap by visible label (unique at tap time); selection is
        // asserted separately via tag + Selected semantics.
        composeTestRule.onNodeWithText(label).performClick()
        composeTestRule.mainClock.advanceTimeBy(1000)
        composeTestRule.waitForIdle()
    }

    private fun assertTabSelected(label: String) {
        // Selected semantics plus label in one node: the bottom-bar
        // item. Content headers with the same word carry no selection.
        composeTestRule
            .onNode(
                hasText(label, substring = true) and
                    SemanticsMatcher.expectValue(SemanticsProperties.Selected, true)
            )
            .assertExists()
    }

    private fun sealHandleLess() {
        FileDeviceMetadataStore(context).writeAdopted(
            AdoptedDevice(
                deviceId = "11111111-1111-1111-1111-111111111111",
                signalDeviceId = 1,
                registrationId = 4242,
                identityPublicKeyB64 = "aWRlbnRpdHk=",
                signedPrekeyId = 1,
                kyberPrekeyId = 1,
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

    @Test
    fun shell_rendersChatsByDefault_withBottomTabs() {
        sealHandleLess()
        launchShell()

        waitFor("Device bound", substring = true)
        composeTestRule.onNodeWithTag("tab-Chats").assertIsDisplayed()
        composeTestRule.onNodeWithTag("tab-Friends").assertIsDisplayed()
        composeTestRule.onNodeWithTag("tab-Settings").assertIsDisplayed()
        assertTabSelected("Chats")
        // Friends content stays hidden on the Chats destination.
        composeTestRule.onNodeWithText("New friend username").assertDoesNotExist()
    }

    @Test
    fun selectingFriends_showsFriendsContent() {
        sealHandleLess()
        launchShell()

        waitFor("Device bound", substring = true)
        openTab("Friends")
        waitFor("New friend username")
        assertTabSelected("Friends")
        composeTestRule.onNodeWithText("Device bound").assertDoesNotExist()
    }

    @Test
    fun selectingSettings_showsSettingsContent() {
        sealHandleLess()
        launchShell()

        waitFor("Device bound", substring = true)
        openTab("Settings")
        // Slice F: the placeholder is gone; the Account section header
        // marks the destination with equal strength.
        waitFor("Account")
        assertTabSelected("Settings")
        composeTestRule.onNodeWithText("Log out").performScrollTo()
        composeTestRule.onNodeWithText("Log out").assertIsDisplayed()
    }

    @Test
    fun chatDetail_opensFromRow_andBackReturnsToChats() {
        sealLocalDevice()
        seedInbound("conv-1", "m-1", 1L, "bob-dev-1", "detail-shell-ui")
        launchShell()

        waitFor("bob")
        composeTestRule.onNodeWithText("bob").performScrollTo()
        composeTestRule.onNodeWithText("bob").performClick()
        // Shell top-bar Back is the only Back affordance in Detail.
        waitFor("Back")
        composeTestRule.onNodeWithText("detail-shell-ui").performScrollTo()
        composeTestRule.onNodeWithText("detail-shell-ui").assertIsDisplayed()
        // Full-screen conversation: no bottom bar.
        composeTestRule.onNodeWithText("Settings").assertDoesNotExist()

        composeTestRule.onNodeWithText("Back").performClick()
        waitFor("Conversations")
        composeTestRule.onNodeWithText("Settings").assertIsDisplayed()
        assertTabSelected("Chats")
    }

    @Test
    fun selectingChatsTab_returnsFromFriends() {
        sealHandleLess()
        launchShell()

        waitFor("Device bound", substring = true)
        openTab("Friends")
        waitFor("New friend username")

        composeTestRule.onNodeWithText("Chats").performClick()
        waitFor("Device bound", substring = true)
        assertTabSelected("Chats")
        composeTestRule.onNodeWithText("New friend username").assertDoesNotExist()
    }

    @Test
    fun unauthenticated_showsLoginWithoutTabs() {
        composeTestRule.setContent {
            SamvaadTheme {
                SessionGate(
                    authApi = FakeAuthApi(),
                    sessionStore = FileSessionStore(context, keys),
                )
            }
        }

        waitFor("Server address")
        composeTestRule.onNodeWithText("Server address").assertIsDisplayed()
        composeTestRule.onNodeWithText("Chats").assertDoesNotExist()
        composeTestRule.onNodeWithText("Friends").assertDoesNotExist()
        composeTestRule.onNodeWithText("Settings").assertDoesNotExist()
    }
}
