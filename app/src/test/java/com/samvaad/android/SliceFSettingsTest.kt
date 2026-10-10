package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.db.MessageDatabase
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
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.ui.shell.SamvaadAppShell
import com.samvaad.android.ui.shell.SettingsSection
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.File
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
 * Slice F Settings tests (host-side via Robolectric).
 *
 * Direct [SettingsSection] renders cover sections/rows/warnings with
 * fabricated (but honestly-shaped) state — no network; the shell-
 * integrated flow proves logout through the real guarded path
 * (revoke best-effort, session wipe, return to login). Typed strings
 * here are fake sentinels.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceFSettingsTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun adopted(
        hasLocalKeys: Boolean = true,
        codesAcknowledged: Boolean = true,
    ) = AdoptedDevice(
        deviceId = "11111111-1111-1111-1111-111111111111",
        signalDeviceId = 1,
        registrationId = 4242,
        identityPublicKeyB64 = "aWRlbnRpdHk=",
        signedPrekeyId = 1,
        kyberPrekeyId = 1,
        otpkHighWaterMark = 100,
        roleHint = "PRIMARY",
        statusHint = "ACTIVE",
        identityHandleId = if (hasLocalKeys) "handle-id" else null,
        signedHandleId = if (hasLocalKeys) "handle-signed" else null,
        kyberHandleId = if (hasLocalKeys) "handle-kyber" else null,
        otpkHandleIds = if (hasLocalKeys) listOf("handle-otpk") else emptyList(),
        codesAcknowledged = codesAcknowledged,
    )

    private fun render(
        identifier: String = "alice",
        serverAddress: String = "https://example.test:8080",
        device: AdoptedDevice? = adopted(),
        onLogout: () -> Unit = {},
    ) {
        composeTestRule.setContent {
            SamvaadTheme {
                SettingsSection(
                    identifier = identifier,
                    serverAddress = serverAddress,
                    adopted = device,
                    onLogout = onLogout,
                )
            }
        }
    }

    // ---- Sections ----

    @Test
    fun readyDevice_rendersAccountDeviceAndSession() {
        render()

        composeTestRule.onNodeWithTag("SettingsList").assertIsDisplayed()
        composeTestRule.onNodeWithText("Settings").assertIsDisplayed()
        composeTestRule.onNodeWithText("Account").assertIsDisplayed()
        composeTestRule.onNodeWithText("alice").assertIsDisplayed()
        composeTestRule.onNodeWithText("https://example.test:8080")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Device").assertIsDisplayed()
        composeTestRule.onNodeWithText("PRIMARY").assertIsDisplayed()
        composeTestRule.onNodeWithText("ACTIVE").assertIsDisplayed()
        composeTestRule.onNodeWithText("#1").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithText("Ready").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithText("Session").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithText("Log out").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun rows_announceLabelAndValueTogether() {
        render()

        composeTestRule.onNodeWithContentDescription("Username, alice")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("Role, PRIMARY")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("Messaging, Ready")
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun handleLess_showsLimited_withWarning_andNoReady() {
        render(device = adopted(hasLocalKeys = false))

        composeTestRule.onNodeWithText("Limited").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithText("Ready").assertDoesNotExist()
        composeTestRule
            .onNodeWithText("holds no private messaging keys", substring = true)
            .performScrollTo()
            .assertIsDisplayed()
        // Non-secret identity facts still render.
        composeTestRule.onNodeWithText("PRIMARY").assertIsDisplayed()
        composeTestRule.onNodeWithText("#1").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun unacknowledgedCodes_showsWarning() {
        render(device = adopted(codesAcknowledged = false))

        composeTestRule
            .onNodeWithText("Recovery codes were not confirmed", substring = true)
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun noAdopted_showsSetupNote_andKeepsAccountAndLogout() {
        render(device = null)

        composeTestRule.onNodeWithText("This device is not set up yet.")
            .performScrollTo()
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Role").assertDoesNotExist()
        composeTestRule.onNodeWithText("alice").assertIsDisplayed()
        composeTestRule.onNodeWithText("Log out").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun longServerAddress_rendersWithoutCrashing() {
        render(serverAddress = "https://very-long-server-name-f.example.test:8080")

        composeTestRule
            .onNodeWithText(
                "https://very-long-server-name-f.example.test:8080",
            )
            .assertIsDisplayed()
    }

    // ---- Logout wiring ----

    @Test
    fun logout_isClickable_andReportsTap() {
        var tapped = false
        render(onLogout = { tapped = true })

        composeTestRule.onNodeWithText("Log out").performScrollTo()
        composeTestRule.onNodeWithText("Log out")
            .assertIsDisplayed()
            .assertIsEnabled()
            .assertHasClickAction()
        composeTestRule.onNodeWithText("Log out").performClick()
        assertTrue(tapped)
    }

    // ---- Integrated shell logout (Done path, real store) ----

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

    private class FakeAuth : AuthApi {
        var logoutCalls = 0

        override suspend fun login(request: LoginRequest): AuthSession =
            throw AssertionError("no login in this slice")

        override suspend fun refresh(
            serverAddress: String,
            refreshToken: String,
        ): RefreshedSession = throw AssertionError("no refresh in this slice")

        override suspend fun logout(serverAddress: String, accessToken: String) {
            logoutCalls++
        }
    }

    private lateinit var context: Context
    private lateinit var keys: EphemeralKeys
    private lateinit var auth: FakeAuth

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
        keys = EphemeralKeys()
        auth = FakeAuth()
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
    fun shell_logout_revokesWipesAndReturnsToLogin() {
        // Handle-less adopted install: Done with limited messaging.
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
        val store = FileSessionStore(context, keys)
        val coordinator = EnrollmentCoordinator(
            api = FakeE2ee(),
            metadata = FileDeviceMetadataStore(context),
            adapter = AndroidSignalAdapter(),
            vault = AndroidCryptoVault(context, keys),
        )
        var loggedOut = false
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadAppShell(
                    identifier = "alice",
                    session = session,
                    serverAddress = "https://example.test:8080",
                    coordinator = coordinator,
                    authApi = auth,
                    sessionStore = store,
                    deviceApi = FakeE2ee(),
                    wrappingKeys = keys,
                    friendsApi = FakeFriends(),
                    onLogout = { loggedOut = true },
                )
            }
        }

        // New Settings content through the real section wiring.
        composeTestRule.onNodeWithText("Settings").performClick()
        waitFor("Account")
        composeTestRule.onNodeWithText("alice").assertIsDisplayed()
        composeTestRule.onNodeWithText("Limited").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithText("Log out").performScrollTo()
        composeTestRule.onNodeWithText("Log out").performClick()
        // Guarded flow: server revoke best-effort, local wipe, exit.
        composeTestRule.waitUntil(60_000) { loggedOut }
        assertEquals(1, auth.logoutCalls)
        assertNull(store.load())
    }
}
