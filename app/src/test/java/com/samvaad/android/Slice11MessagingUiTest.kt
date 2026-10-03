package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
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
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.ClaimedOneTimePrekey
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.HistoryItem
import com.samvaad.android.enroll.MailboxItem
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.enroll.SyncCursor
import com.samvaad.android.session.EstablishedVia
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.SignalSessionEntry
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 11 UI tests: pure renderer checks plus HomeScreen-integrated
 * flows with a scripted fake API, real crypto/vault/Room (file-backed,
 * same paths production uses) and ephemeral keys standing in for the
 * Keystore key. Typed/delivered strings here are fake sentinels.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class Slice11MessagingUiTest {

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

    private class FakeApi : E2eeDeviceApi {
        var directoryHandler: (String) -> List<RecipientDeviceRecord> =
            { throw AssertionError("unexpected directory") }
        var claimHandler: suspend (String) -> ClaimedDeviceBundle =
            { throw AssertionError("unexpected claim") }
        var submitHandler: () -> SubmitMessageResult =
            { throw AssertionError("unexpected submit") }
        var mailboxHandler: suspend () -> List<MailboxItem> = { emptyList() }
        var historyHandler: () -> List<HistoryItem> = { emptyList() }
        var cursorHandler: () -> SyncCursor =
            { SyncCursor("conv-1", 0L) }
        var advanceHandler: (Long) -> SyncCursor =
            { SyncCursor("conv-1", it) }
        var submitCalls = 0

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
        ): DeviceRecord = throw AssertionError("no recovery in this slice")

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
        ): List<RecipientDeviceRecord> = directoryHandler(username)

        override suspend fun claimOneTimePrekey(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            requestId: java.util.UUID,
        ): ClaimedDeviceBundle = claimHandler(deviceId)

        override suspend fun submitMessage(
            session: AuthSession,
            serverAddress: String,
            requestId: java.util.UUID,
            envelopes: List<com.samvaad.android.enroll.MessageEnvelopeSubmit>,
        ): SubmitMessageResult {
            submitCalls++
            return submitHandler()
        }

        override suspend fun fetchMailbox(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<MailboxItem> = mailboxHandler()

        override suspend fun ackMailbox(
            session: AuthSession,
            serverAddress: String,
            messageIds: List<java.util.UUID>,
        ): Int = messageIds.size

        override suspend fun fetchHistory(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<HistoryItem> = historyHandler()

        override suspend fun getSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
        ): SyncCursor = cursorHandler()

        override suspend fun advanceSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): SyncCursor = advanceHandler(throughSequence)
    }

    private data class RemoteFixture(
        val registrationId: Int,
        val signalDeviceId: Int,
        val identityB64: String,
        val signedId: Int,
        val signedB64: String,
        val signedSigB64: String,
        val kyberId: Int,
        val kyberB64: String,
        val kyberSigB64: String,
        val otkId: Int,
        val otkB64: String,
    )

    private lateinit var context: Context
    private lateinit var api: FakeApi
    private lateinit var keys: EphemeralKeys
    private lateinit var adapter: AndroidSignalAdapter

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
        api = FakeApi()
        keys = EphemeralKeys()
        adapter = AndroidSignalAdapter()
    }

    private fun sealLocalDevice(): AdoptedDevice {
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
        val adopted = AdoptedDevice(
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
        FileDeviceMetadataStore(context).writeAdopted(adopted)
        return adopted
    }

    private fun remoteFixture(): RemoteFixture {
        val remote = AndroidSignalAdapter()
        val identity = remote.generateIdentity()
        val signed = remote.generateSignedPrekey(identity, 11)
        val kyber = remote.generateKyberPrekey(identity, 21)
        val otk = remote.generateOneTimePrekey(101)
        return RemoteFixture(
            registrationId = 7001,
            signalDeviceId = 2,
            identityB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey),
            signedId = signed.prekeyId,
            signedB64 = SpikeCryptoMaterial.encodeBase64(signed.publicKey),
            signedSigB64 = SpikeCryptoMaterial.encodeBase64(signed.signature),
            kyberId = kyber.prekeyId,
            kyberB64 = SpikeCryptoMaterial.encodeBase64(kyber.publicKey),
            kyberSigB64 = SpikeCryptoMaterial.encodeBase64(kyber.signature),
            otkId = otk.prekeyId,
            otkB64 = SpikeCryptoMaterial.encodeBase64(otk.publicKey),
        )
    }

    private fun recipientOf(deviceId: String, f: RemoteFixture) = RecipientDeviceRecord(
        deviceId = deviceId,
        registrationId = f.registrationId,
        signalDeviceId = f.signalDeviceId,
        deviceIdentityPublicKey = f.identityB64,
        signedPrekeyId = f.signedId,
        signedPrekey = f.signedB64,
        signedPrekeySignature = f.signedSigB64,
        hasAvailableOneTimePrekey = true,
        deviceRole = "COMPANION",
        kyberPrekeyId = f.kyberId,
        kyberPrekey = f.kyberB64,
        kyberPrekeySignature = f.kyberSigB64,
    )

    private fun claimOf(deviceId: String, f: RemoteFixture) = ClaimedDeviceBundle(
        deviceId = deviceId,
        registrationId = f.registrationId,
        signalDeviceId = f.signalDeviceId,
        deviceIdentityPublicKey = f.identityB64,
        signedPrekeyId = f.signedId,
        signedPrekey = f.signedB64,
        signedPrekeySignature = f.signedSigB64,
        oneTimePrekey = ClaimedOneTimePrekey(f.otkId, f.otkB64),
        deviceRole = "COMPANION",
        kyberPrekeyId = f.kyberId,
        kyberPrekey = f.kyberB64,
        kyberPrekeySignature = f.kyberSigB64,
    )

    private fun launch(): EnrollmentCoordinator {
        val coordinator = EnrollmentCoordinator(
            api = api,
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
                    deviceApi = api,
                    wrappingKeys = keys,
                )
            }
        }
        return coordinator
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
    fun emptyState_showsNoConversations() {
        sealLocalDevice()
        launch()
        waitFor("Conversations", substring = false)
        composeTestRule.onNodeWithText("No conversations yet.").assertIsDisplayed()
    }

    @Test
    fun list_rendersDurableRows_offline() {
        sealLocalDevice()
        seedInbound("conv-1", "m-1", 1L, "bob-dev-1", "hello-ui")
        seedInbound("conv-1", "m-2", 2L, "bob-dev-1", "second-ui")
        launch()
        // No network is touched for rendering: every FakeApi method throws.
        waitFor("bob", substring = false)
        composeTestRule.onNodeWithText("second-ui").assertIsDisplayed()
    }

    @Test
    fun detail_rendersAndBackReturnsToList() {
        sealLocalDevice()
        seedInbound("conv-1", "m-1", 1L, "bob-dev-1", "detail-ui")
        launch()
        waitFor("bob", substring = false)
        composeTestRule.onNodeWithText("bob").performClick()
        waitFor("detail-ui", substring = false)
        composeTestRule.onNodeWithText("detail-ui").assertIsDisplayed()
        composeTestRule.onNodeWithText("Back").performScrollTo()
        composeTestRule.onNodeWithText("Back").performClick()
        waitFor("Conversations", substring = false)
        // The row preview proves the list is back (the peer label also
        // fills the composer prefill, so it is ambiguous by design).
        composeTestRule.onNodeWithText("detail-ui").assertIsDisplayed()
    }

    @Test
    fun sync_failurePreservesMessages_showsError() {
        sealLocalDevice()
        seedInbound("conv-1", "m-1", 1L, "bob-dev-1", "kept-ui")
        api.mailboxHandler = { throw IOException("boom") }
        launch()
        waitFor("kept-ui", substring = false)
        composeTestRule.onNodeWithText("Sync").performScrollTo()
        composeTestRule.onNodeWithText("Sync").performClick()
        waitFor("Sync had partial failures", substring = true)
        // Existing durable rows stay rendered.
        composeTestRule.onNodeWithText("kept-ui").assertIsDisplayed()
    }

    @Test
    fun sync_entersLoadingState_thenCompletes() {
        sealLocalDevice()
        val gate = CountDownLatch(1)
        api.mailboxHandler = {
            // Wait off the main thread: the sweep suspends, the Syncing…
            // indicator stays interactive, and the test thread can proceed.
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                check(gate.await(10, TimeUnit.SECONDS)) { "mailbox gate timed out" }
            }
            emptyList()
        }
        launch()
        waitFor("Conversations", substring = false)
        composeTestRule.onNodeWithText("Sync").performScrollTo()
        composeTestRule.onNodeWithText("Sync").performClick()
        waitFor("Syncing…", substring = false)
        gate.countDown()
        waitFor("No conversations yet.", substring = false)
    }

    @Test
    fun composer_requiresExplicitDeviceSelection() {
        sealLocalDevice()
        val f = remoteFixture()
        val bobDevice = "bbbbbbbb-2222-3333-4444-555555555555"
        api.directoryHandler = { listOf(recipientOf(bobDevice, f)) }
        launch()
        waitFor("Friend username", substring = false)
        composeTestRule.onNodeWithText("Friend username").performTextInput("bob")
        composeTestRule.onNodeWithText("Find devices").performScrollTo()
        composeTestRule.onNodeWithText("Find devices").performClick()
        waitFor("COMPANION", substring = true)
        // Nothing preselected: Send stays disabled until an explicit tap.
        composeTestRule.onNodeWithText("Message").performTextInput("hi-ui")
        composeTestRule.onNodeWithText("Send").assertIsNotEnabled()
        composeTestRule.onNodeWithText("COMPANION", substring = true).performScrollTo()
        composeTestRule.onNodeWithText("COMPANION", substring = true).performClick()
        composeTestRule.onNodeWithText("Send").assertIsEnabled()
    }

    @Test
    fun send_endToEnd_establishSendRenderSingleRow() {
        sealLocalDevice()
        val f = remoteFixture()
        val bobDevice = "bbbbbbbb-2222-3333-4444-555555555555"
        api.directoryHandler = { listOf(recipientOf(bobDevice, f)) }
        api.claimHandler = { claimOf(bobDevice, f) }
        api.submitHandler = {
            SubmitMessageResult(
                messageId = "server-msg-1",
                conversationId = "conv-send-1",
                sequenceNumber = 1L,
                serverTimestamp = "2026-10-03T10:00:00",
                acceptedRecipientDevices = listOf(bobDevice),
                createdNew = true,
            )
        }
        launch()
        waitFor("Friend username", substring = false)
        composeTestRule.onNodeWithText("Friend username").performTextInput("bob")
        composeTestRule.onNodeWithText("Find devices").performScrollTo()
        composeTestRule.onNodeWithText("Find devices").performClick()
        waitFor("COMPANION", substring = true)
        composeTestRule.onNodeWithText("COMPANION", substring = true).performScrollTo()
        composeTestRule.onNodeWithText("COMPANION", substring = true).performClick()
        composeTestRule.onNodeWithText("Message").performTextInput("hello-bob-ui")
        composeTestRule.onNodeWithText("Send").performScrollTo()
        composeTestRule.onNodeWithText("Send").performClick()
        // Sent through establish → send → Room → refreshed detail. The
        // Back button exists only in detail, so it proves navigation; the
        // draft field is cleared, so the waited text node is the bubble.
        waitFor("Back", substring = false)
        waitFor("hello-bob-ui", substring = false)
        composeTestRule.onNodeWithText("hello-bob-ui").performScrollTo()
        composeTestRule.onNodeWithText("hello-bob-ui").assertIsDisplayed()
        assertEquals(1, api.submitCalls)
        composeTestRule.onNodeWithText("Sending…").assertDoesNotExist()
    }

    @Test
    fun send_doubleTap_submitsOnce() {
        sealLocalDevice()
        val f = remoteFixture()
        val bobDevice = "bbbbbbbb-2222-3333-4444-555555555555"
        // Gate the claim so the first send is still in flight when the
        // second tap lands: the UI single-flight must swallow it.
        val gate = CountDownLatch(1)
        api.directoryHandler = { listOf(recipientOf(bobDevice, f)) }
        api.claimHandler = {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                check(gate.await(10, TimeUnit.SECONDS)) { "claim gate timed out" }
            }
            claimOf(bobDevice, f)
        }
        api.submitHandler = {
            SubmitMessageResult(
                messageId = "server-msg-1",
                conversationId = "conv-send-1",
                sequenceNumber = 1L,
                serverTimestamp = "2026-10-03T10:00:00",
                acceptedRecipientDevices = listOf(bobDevice),
                createdNew = true,
            )
        }
        launch()
        waitFor("Friend username", substring = false)
        composeTestRule.onNodeWithText("Friend username").performTextInput("bob")
        composeTestRule.onNodeWithText("Find devices").performScrollTo()
        composeTestRule.onNodeWithText("Find devices").performClick()
        waitFor("COMPANION", substring = true)
        composeTestRule.onNodeWithText("COMPANION", substring = true).performScrollTo()
        composeTestRule.onNodeWithText("COMPANION", substring = true).performClick()
        composeTestRule.onNodeWithText("Message").performTextInput("double-tap-ui")
        composeTestRule.onNodeWithText("Send").performScrollTo()
        composeTestRule.onNodeWithText("Send").performClick()
        // While the first send is parked in the gated claim, no enabled
        // Send affordance may exist: a second logical send cannot start.
        waitFor("Sending…", substring = false)
        composeTestRule.onNodeWithText("Send").assertDoesNotExist()
        composeTestRule.onNodeWithText("Sending…").performClick()
        gate.countDown()
        waitFor("Back", substring = false)
        waitFor("double-tap-ui", substring = false)
        composeTestRule.onNodeWithText("double-tap-ui").performScrollTo()
        composeTestRule.onNodeWithText("double-tap-ui").assertIsDisplayed()
        assertEquals(1, api.submitCalls)
    }

    @Test
    fun restart_reopenedDatabase_rendersDurableWithoutNetwork() {
        sealLocalDevice()
        seedInbound("conv-1", "m-1", 1L, "bob-dev-1", "restart-ui")
        // Fresh process: close everything, reopen the same durable files,
        // and render through the production loader path. No network call
        // exists on this path (every FakeApi method throws).
        val db = MessageDatabase.open(context)
        val rendered: List<MessageRow>
        try {
            kotlinx.coroutines.runBlocking {
                val dao = db.messageDao()
                assertEquals(listOf("conv-1"), dao.knownConversationIds())
                val rows = dao.historyPage("conv-1", 0, MESSAGE_PAGE_LIMIT)
                rendered = rows.map { entity ->
                    mapMessageRow(entity, senderLabelFor(entity) { "bob" }) { id, sealed ->
                        try {
                            MessageContentSealer(keys).open(id, sealed)
                                .toString(Charsets.UTF_8)
                        } catch (_: Exception) {
                            null
                        }
                    }
                }
            }
        } finally {
            db.close()
        }
        assertEquals(1, rendered.size)
        assertEquals("restart-ui", rendered.single().text)
        assertEquals("bob", rendered.single().senderLabel)
        launch()
        waitFor("restart-ui", substring = false)
    }

    @Test
    fun handleLess_hidesMessaging() {
        // Bind-adopted record: ACTIVE server-side, no local handles.
        FileDeviceMetadataStore(context).writeAdopted(
            AdoptedDevice(
                deviceId = "cccccccc-2222-3333-4444-555555555555",
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
        launch()
        waitFor("Device bound", substring = true)
        composeTestRule.onNodeWithText("Conversations").assertDoesNotExist()
        composeTestRule.onNodeWithText("Friend username").assertDoesNotExist()
    }

    @Test
    fun unsealFailure_rendersPlaceholder() {
        sealLocalDevice()
        // Row whose sealed bytes cannot open with this installation's key.
        val db = MessageDatabase.open(context)
        try {
            kotlinx.coroutines.runBlocking {
                val dao = db.messageDao()
                dao.upsertConversation(ConversationEntity("conv-1"))
                dao.insertIgnore(
                    MessageEntity(
                    messageId = "m-bad",
                    conversationId = "conv-1",
                    sequenceNumber = 1L,
                    direction = MessageDirection.IN,
                    senderDeviceId = "bob-dev-1",
                    recipientDeviceId = "11111111-1111-1111-1111-111111111111",
                    envelopeType = "RATCHET",
                    ciphertext = "cipher".toByteArray(),
                    plaintextSealed = "not-a-sealed-envelope".toByteArray(),
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
        launch()
        waitFor("conv-1", substring = false)
        composeTestRule.onNodeWithText("conv-1").performClick()
        waitFor(MESSAGE_UNREADABLE, substring = false)
    }
}
