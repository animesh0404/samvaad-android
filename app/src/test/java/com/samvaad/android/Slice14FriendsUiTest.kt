package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.printToLog
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.ClaimedDeviceBundle
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.HistoryItem
import com.samvaad.android.enroll.MailboxItem
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.SubmitMessageResult
import com.samvaad.android.enroll.SyncBatchItem
import com.samvaad.android.enroll.SyncCursor
import com.samvaad.android.enroll.SyncUploadRequest
import com.samvaad.android.enroll.SyncUploadResult
import com.samvaad.android.enroll.SyncAckResult
import com.samvaad.android.friends.FriendEntry
import com.samvaad.android.friends.FriendException
import com.samvaad.android.friends.FriendRequestRecord
import com.samvaad.android.friends.FriendsApi
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.IOException
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 14 UI tests: Friends section renderer checks plus
 * HomeScreen-integrated flows (add friend, accept incoming) with a
 * scripted fake [FriendsApi].
 *
 * The integrated flows run in the handle-less bound state (adopted
 * metadata without key handles): the Friends section is session-level
 * and renders there, while messaging stays fail-closed. Typed strings
 * here are fake sentinels.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class Slice14FriendsUiTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )

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
        ): com.samvaad.android.enroll.AttachBegin =
            throw AssertionError("no attach in this slice")

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
            request: SyncUploadRequest,
        ): SyncUploadResult = throw AssertionError("no sync in this slice")

        override suspend fun fetchSyncBatch(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<SyncBatchItem> = throw AssertionError("no sync in this slice")

        override suspend fun ackSync(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): SyncAckResult = throw AssertionError("no sync in this slice")
    }

    private class FakeFriends : FriendsApi {
        var friends: List<FriendEntry> = emptyList()
        var incoming: List<FriendRequestRecord> = emptyList()
        val sentTo = mutableListOf<String>()
        val accepted = mutableListOf<String>()
        val rejected = mutableListOf<String>()
        var sendHandler: (String) -> FriendRequestRecord = { username ->
            requestOf(recipientUsername = username)
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
        ): FriendRequestRecord {
            sentTo.add(username)
            return sendHandler(username)
        }

        override suspend fun listIncoming(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendRequestRecord> = incoming

        override suspend fun listOutgoing(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendRequestRecord> = emptyList()

        override suspend fun acceptRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord {
            accepted.add(requestId)
            // Accepting clears the pending row and grows the roster,
            // like the server does.
            incoming = incoming.filterNot { it.requestId == requestId }
            friends = friends + FriendEntry("22222222-2222-2222-2222-222222222222", "bob")
            return requestOf(status = "ACCEPTED")
        }

        override suspend fun rejectRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord {
            rejected.add(requestId)
            incoming = incoming.filterNot { it.requestId == requestId }
            return requestOf(status = "REJECTED")
        }

        override suspend fun cancelRequest(
            session: AuthSession,
            serverAddress: String,
            requestId: String,
        ): FriendRequestRecord = throw AssertionError("no cancel in this slice")

        override suspend fun listFriends(
            session: AuthSession,
            serverAddress: String,
        ): List<FriendEntry> = friends
    }

    private fun launch(friendsApi: FakeFriends) {
        // Handle-less bound install: Friends renders in Done while
        // messaging stays fail-closed (no keys, no network).
        FileDeviceMetadataStore(context).writeAdopted(
            AdoptedDevice(
                deviceId = "11111111-1111-1111-1111-111111111111",
                signalDeviceId = 1,
                registrationId = 7001,
                identityPublicKeyB64 = "aXg=",
                signedPrekeyId = 11,
                kyberPrekeyId = null,
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
        val coordinator = EnrollmentCoordinator(
            api = FakeE2ee(),
            metadata = FileDeviceMetadataStore(context),
            adapter = AndroidSignalAdapter(),
            vault = AndroidCryptoVault(context, EphemeralKeys()),
        )
        composeTestRule.setContent {
            SamvaadTheme {
                HomeScreen(
                    identifier = "alice",
                    session = session,
                    serverAddress = "https://example.test:8080",
                    coordinator = coordinator,
                    deviceApi = FakeE2ee(),
                    wrappingKeys = EphemeralKeys(),
                    friendsApi = friendsApi,
                )
            }
        }
    }

    private fun waitFor(text: String) {
        composeTestRule.waitUntil(60_000) {
            try {
                composeTestRule.onNodeWithText(text).fetchSemanticsNode()
                true
            } catch (_: AssertionError) {
                false
            }
        }
    }

    @Test
    fun emptyRoster_showsEmptyState_andAddAffordance() {
        launch(FakeFriends())
        waitFor("No friends yet. Add someone above.")
        composeTestRule.onNodeWithText("Friends").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithText("Add friend").performScrollTo().assertIsDisplayed()
        composeTestRule.onNodeWithText("Refresh friends").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun addFriend_sendsRequest_andShowsConfirmation() {
        val fake = FakeFriends()
        launch(fake)
        waitFor("No friends yet. Add someone above.")
        composeTestRule.onNodeWithText("New friend username").performScrollTo()
            .performTextInput("bob")
        composeTestRule.onNodeWithText("Add friend").performScrollTo().performClick()
        waitFor("Request sent to bob.")
        assertEquals(listOf("bob"), fake.sentTo)
    }

    @Test
    fun addFriend_unknownUser_showsNotFound() {
        val fake = FakeFriends().apply {
            sendHandler = { throw FriendException.NotFound() }
        }
        launch(fake)
        waitFor("No friends yet. Add someone above.")
        composeTestRule.onNodeWithText("New friend username").performScrollTo()
            .performTextInput("ghost")
        composeTestRule.onNodeWithText("Add friend").performScrollTo().performClick()
        waitFor("User not found. Check the name and try again.")
        assertEquals(listOf("ghost"), fake.sentTo)
    }

    @Test
    fun incomingRequest_accept_movesSenderToFriends() {
        val fake = FakeFriends().apply {
            incoming = listOf(requestOf())
        }
        launch(fake)
        waitFor("Request from bob")
        composeTestRule.onNodeWithText("Accept").performScrollTo().performClick()
        waitFor("bob")
        assertEquals(listOf("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), fake.accepted)
        assertTrue(fake.rejected.isEmpty())
    }

    @Test
    fun incomingRequest_reject_clearsRow() {
        val fake = FakeFriends().apply {
            incoming = listOf(requestOf())
        }
        launch(fake)
        waitFor("Request from bob")
        composeTestRule.onNodeWithText("Reject").performScrollTo().performClick()
        composeTestRule.waitUntil(60_000) {
            try {
                composeTestRule.onNodeWithText("Request from bob").fetchSemanticsNode()
                false
            } catch (_: AssertionError) {
                true
            }
        }
        assertEquals(listOf("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), fake.rejected)
        assertTrue(fake.accepted.isEmpty())
    }

    private class EphemeralKeys : com.samvaad.android.crypto.WrappingKeyProvider {
        private var key: javax.crypto.SecretKey? = null
        override fun getOrCreate(): javax.crypto.SecretKey =
            key ?: javax.crypto.KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): javax.crypto.SecretKey? = key
    }

    companion object {
        private fun requestOf(
            recipientUsername: String = "alice",
            status: String = "PENDING",
        ): FriendRequestRecord = FriendRequestRecord(
            requestId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            senderUserId = "22222222-2222-2222-2222-222222222222",
            senderUsername = "bob",
            recipientUserId = "11111111-1111-1111-1111-111111111111",
            recipientUsername = recipientUsername,
            status = status,
            createdAt = "2026-10-05T10:00:00",
            respondedAt = null,
        )
    }
}
