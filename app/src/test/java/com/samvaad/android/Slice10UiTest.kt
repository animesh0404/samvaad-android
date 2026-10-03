package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollRequest
import com.samvaad.android.enroll.EnrollResult
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.OneTimePrekeyUpload
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.File
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
 * Slice 10 UI handoff through the real [HomeScreen] wiring with a scripted
 * fake API and real crypto/vault: pending check-status, denied set-up-again,
 * recovery code entry/clearing, bind picker, and the active-side approval
 * surface. Codes typed here are fake sentinels, asserted absent afterwards.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class Slice10UiTest {

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

    private class FakeApi10 : E2eeDeviceApi {
        var enrollHandler: (EnrollRequest) -> EnrollResult =
            { throw AssertionError("unexpected enroll") }
        var uploadHandler: (String, List<OneTimePrekeyUpload>) -> Unit = { _, _ -> }
        var listHandler: () -> DeviceList =
            { DeviceList("ENROLLED_ACTIVE", emptyList()) }
        var approveHandler: (String) -> DeviceRecord =
            { throw AssertionError("unexpected approve") }
        var bindHandler: (String, String) -> DeviceRecord =
            { _, _ -> throw AssertionError("unexpected bind") }
        var recoverHandler: (String, EnrollRequest) -> DeviceRecord =
            { _, _ -> throw AssertionError("unexpected recoverEnroll") }
        var approveCalls = 0
        val uploads = mutableListOf<Pair<String, List<OneTimePrekeyUpload>>>()

        override suspend fun enroll(
            session: AuthSession,
            serverAddress: String,
            request: EnrollRequest,
        ): EnrollResult = enrollHandler(request)

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) {
            uploads.add(deviceId to batch)
            uploadHandler(deviceId, batch)
        }

        override suspend fun listDevices(
            session: AuthSession,
            serverAddress: String,
        ): DeviceList = listHandler()

        override suspend fun approveDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
        ): DeviceRecord {
            approveCalls++
            return approveHandler(deviceId)
        }

        override suspend fun bindDevice(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            recoveryCode: String,
        ): DeviceRecord = bindHandler(deviceId, recoveryCode)

        override suspend fun recoverEnroll(
            session: AuthSession,
            serverAddress: String,
            recoveryCode: String,
            request: EnrollRequest,
        ): DeviceRecord = recoverHandler(recoveryCode, request)

        override suspend fun listRecipientDevices(
            session: AuthSession,
            serverAddress: String,
            username: String,
        ): List<com.samvaad.android.enroll.RecipientDeviceRecord> =
            throw AssertionError("no discovery in this slice")

        override suspend fun claimOneTimePrekey(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            requestId: java.util.UUID,
        ): com.samvaad.android.enroll.ClaimedDeviceBundle =
            throw AssertionError("no discovery in this slice")

        override suspend fun submitMessage(
            session: AuthSession,
            serverAddress: String,
            requestId: java.util.UUID,
            envelopes: List<com.samvaad.android.enroll.MessageEnvelopeSubmit>,
        ): com.samvaad.android.enroll.SubmitMessageResult =
            throw AssertionError("no submission in this slice")

        override suspend fun fetchMailbox(
            session: AuthSession,
            serverAddress: String,
            limit: Int,
        ): List<com.samvaad.android.enroll.MailboxItem> =
            throw AssertionError("no inbox in this slice")

        override suspend fun ackMailbox(
            session: AuthSession,
            serverAddress: String,
            messageIds: List<java.util.UUID>,
        ): Int = throw AssertionError("no inbox in this slice")

        override suspend fun fetchHistory(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            afterSequence: Long,
            limit: Int,
        ): List<com.samvaad.android.enroll.HistoryItem> =
            throw AssertionError("no history in this slice")

        override suspend fun getSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
        ): com.samvaad.android.enroll.SyncCursor =
            throw AssertionError("no history in this slice")

        override suspend fun advanceSyncCursor(
            session: AuthSession,
            serverAddress: String,
            conversationId: String,
            throughSequence: Long,
        ): com.samvaad.android.enroll.SyncCursor =
            throw AssertionError("no history in this slice")
    }

    private lateinit var context: Context
    private lateinit var api: FakeApi10
    private lateinit var metadata: FileDeviceMetadataStore

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
        api = FakeApi10()
        metadata = FileDeviceMetadataStore(context)
    }

    private fun launch(): EnrollmentCoordinator {
        val coordinator = EnrollmentCoordinator(
            api = api,
            metadata = metadata,
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

    private fun pendingRow(identityB64: String, status: String) = DeviceRecord(
        deviceId = "aaaaaaaa-2222-3333-4444-555555555555",
        registrationId = 4242,
        signalDeviceId = 2,
        deviceIdentityPublicKey = identityB64,
        signedPrekeyId = 1,
        deviceRole = "COMPANION",
        status = status,
        availablePrekeys = 0,
    )

    @Test
    fun pending_showsCheckStatus_andConvergesToActive() {
        var listed: List<DeviceRecord> = emptyList()
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listed) }
        api.enrollHandler = { req ->
            val row = pendingRow(req.deviceIdentityPublicKey, "PENDING").copy(registrationId = req.registrationId)
            listed = listOf(row)
            EnrollResult(row, "ENROLLED_ACTIVE", null)
        }
        launch()

        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("waiting for approval", substring = true)
        composeTestRule.onNodeWithText("Check status").assertIsDisplayed()

        listed = listOf(pendingRow(metadata.readAdopted()!!.identityPublicKeyB64, "ACTIVE"))
        composeTestRule.onNodeWithText("Check status").performClick()
        waitFor("Device ready", substring = true)

        assertEquals(1, api.uploads.size)
        assertEquals(100, api.uploads.single().second.size)
    }

    @Test
    fun pending_revoked_showsDenied_andSetUpAgainStartsFresh() {
        var listed: List<DeviceRecord> = emptyList()
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listed) }
        api.enrollHandler = { req ->
            val row = pendingRow(req.deviceIdentityPublicKey, "PENDING").copy(registrationId = req.registrationId)
            listed = listOf(row)
            EnrollResult(row, "ENROLLED_ACTIVE", null)
        }
        launch()
        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("waiting for approval", substring = true)

        listed = listOf(pendingRow("aWRlbnRpdHk=", "REVOKED"))
        composeTestRule.onNodeWithText("Check status").performClick()
        waitFor("was not approved", substring = true)
        composeTestRule.onNodeWithText("Set up this device again").assertIsDisplayed()

        api.enrollHandler = { req ->
            val row = DeviceRecord(
                deviceId = "bbbbbbbb-2222-3333-4444-555555555555",
                registrationId = req.registrationId,
                signalDeviceId = 3,
                deviceIdentityPublicKey = req.deviceIdentityPublicKey,
                signedPrekeyId = req.signedPrekeyId,
                deviceRole = "COMPANION",
                status = "ACTIVE",
                availablePrekeys = 0,
            )
            listed = listOf(row)
            EnrollResult(row, "ENROLLED_ACTIVE", null)
        }
        composeTestRule.onNodeWithText("Set up this device again").performClick()
        waitFor("Device ready", substring = true)
        assertEquals(
            "bbbbbbbb-2222-3333-4444-555555555555",
            metadata.readAdopted()!!.deviceId,
        )
    }

    @Test
    fun recovery_form_acceptsCode_clearsAfterFailedAttempt() {
        api.listHandler = { throw EnrollException.RecoveryRequired() }
        api.recoverHandler = { _, _ -> throw EnrollException.ServerRejected() }
        launch()

        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("needs recovery", substring = true)
        composeTestRule.onNodeWithText("Recovery code").assertIsDisplayed()

        composeTestRule.onNodeWithText("Recovery code").performTextInput("SENTINEL-UI-3")
        composeTestRule.onNodeWithText("Recover as new device").performClick()
        waitFor("was not accepted", substring = true)
        // The transient code is dropped from the field after the attempt.
        composeTestRule.onNodeWithText("SENTINEL-UI-3").assertDoesNotExist()
        val stored = FileDeviceMetadataStore.rawFile(context).readBytes()
        assertFalse(String(stored, Charsets.UTF_8).contains("SENTINEL-UI-3"))
    }

    @Test
    fun recovery_bindExisting_goesActive() {
        val target = DeviceRecord(
            deviceId = "cccccccc-2222-3333-4444-555555555555",
            registrationId = 5150,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VydmVyLWtleQ==",
            signedPrekeyId = 9,
            deviceRole = "PRIMARY",
            status = "ACTIVE",
            availablePrekeys = 42,
        )
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(target)) }
        api.bindHandler = { _, _ -> target }
        // RecoveryRequired on the bootstrap reconcile path.
        var firstList = true
        val delegate = api.listHandler
        api.listHandler = {
            if (firstList) {
                firstList = false
                throw EnrollException.RecoveryRequired()
            }
            delegate()
        }
        launch()

        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("needs recovery", substring = true)
        composeTestRule.onNodeWithText("Recovery code").performTextInput("SENTINEL-UI-4")
        composeTestRule.onNodeWithText("Bind an existing device instead").performScrollTo()
        composeTestRule.onNodeWithText("Bind an existing device instead").performClick()
        waitFor("Bind PRIMARY", substring = true)
        composeTestRule.onNodeWithText("Bind PRIMARY", substring = true).performScrollTo()
        composeTestRule.onNodeWithText("Bind PRIMARY", substring = true).performClick()
        // Bind-adopted installs hold no local keys: the qualified bound
        // state shows, never the unqualified ready message.
        waitFor("Device bound", substring = true)
        composeTestRule.onNodeWithText("Device ready").assertDoesNotExist()

        assertEquals(target.deviceId, metadata.readAdopted()!!.deviceId)
        assertTrue(api.uploads.isEmpty())
    }

    @Test
    fun bindWithoutKeys_showsQualifiedBoundState_notReady() {
        val target = DeviceRecord(
            deviceId = "cccccccc-2222-3333-4444-555555555555",
            registrationId = 5150,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VydmVyLWtleQ==",
            signedPrekeyId = 9,
            deviceRole = "PRIMARY",
            status = "ACTIVE",
            availablePrekeys = 42,
        )
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(target)) }
        api.bindHandler = { _, _ -> target }
        var firstList = true
        val delegate = api.listHandler
        api.listHandler = {
            if (firstList) {
                firstList = false
                throw EnrollException.RecoveryRequired()
            }
            delegate()
        }
        launch()

        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("needs recovery", substring = true)
        composeTestRule.onNodeWithText("Recovery code").performTextInput("SENTINEL-UI-9")
        composeTestRule.onNodeWithText("Bind an existing device instead").performScrollTo()
        composeTestRule.onNodeWithText("Bind an existing device instead").performClick()
        waitFor("Bind PRIMARY", substring = true)
        composeTestRule.onNodeWithText("Bind PRIMARY", substring = true).performScrollTo()
        composeTestRule.onNodeWithText("Bind PRIMARY", substring = true).performClick()
        waitFor("Device bound", substring = true)

        // Qualified state only: the unqualified ready message must not show,
        // and the limitation must be explained without claiming the keys.
        composeTestRule.onNodeWithText("Device ready").assertDoesNotExist()
        composeTestRule.onNodeWithText("not present here", substring = true)
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("recover as a new device", substring = true)
            .assertIsDisplayed()
        assertEquals(target.deviceId, metadata.readAdopted()!!.deviceId)
    }

    @Test
    fun approve_hiddenOnPendingDevice() {
        var listed: List<DeviceRecord> = emptyList()
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listed) }
        api.enrollHandler = { req ->
            val row = pendingRow(req.deviceIdentityPublicKey, "PENDING").copy(registrationId = req.registrationId)
            listed = listOf(row)
            EnrollResult(row, "ENROLLED_ACTIVE", null)
        }
        launch()
        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("waiting for approval", substring = true)
        // A pending-bound session can never approve: no approval surface.
        composeTestRule.onNodeWithText("Review pending devices").assertDoesNotExist()
        composeTestRule.onNodeWithText("Approve").assertDoesNotExist()
    }

    @Test
    fun activeDevice_canApprovePending() {
        val self = DeviceRecord(
            deviceId = "self-1111-2222-3333-444455555555",
            registrationId = 4242,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VsZg==",
            signedPrekeyId = 1,
            deviceRole = "PRIMARY",
            status = "ACTIVE",
            availablePrekeys = 100,
        )
        val other = pendingRow("cGVuZGluZw==", "PENDING")
            .copy(deviceId = "pend-1111-2222-3333-444455555555")
        api.enrollHandler = { req ->
            EnrollResult(self.copy(deviceIdentityPublicKey = req.deviceIdentityPublicKey, registrationId = req.registrationId), "NEVER_ENROLLED", null)
        }
        var approvedNow = false
        api.listHandler = {
            val otherNow = if (approvedNow) other.copy(status = "ACTIVE") else other
            DeviceList("ENROLLED_ACTIVE", listOf(self, otherNow))
        }
        api.approveHandler = {
            approvedNow = true
            other.copy(status = "ACTIVE")
        }
        launch()

        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("Device ready", substring = true)
        composeTestRule.onNodeWithText("Review pending devices").performClick()
        waitFor("Pending device (", substring = true)
        composeTestRule.onNodeWithText("Approve").performClick()
        waitFor("Device approved", substring = true)
        assertEquals(1, api.approveCalls)
    }

    @Test
    fun approve_denied_showsMessage() {
        val self = DeviceRecord(
            deviceId = "self-1111-2222-3333-444455555555",
            registrationId = 4242,
            signalDeviceId = 1,
            deviceIdentityPublicKey = "c2VsZg==",
            signedPrekeyId = 1,
            deviceRole = "PRIMARY",
            status = "ACTIVE",
            availablePrekeys = 100,
        )
        val other = pendingRow("cGVuZGluZw==", "PENDING")
            .copy(deviceId = "pend-1111-2222-3333-444455555555")
        api.enrollHandler = { req ->
            EnrollResult(self.copy(deviceIdentityPublicKey = req.deviceIdentityPublicKey, registrationId = req.registrationId), "NEVER_ENROLLED", null)
        }
        api.listHandler = { DeviceList("ENROLLED_ACTIVE", listOf(self, other)) }
        api.approveHandler = { throw EnrollException.ServerRejected() }
        launch()

        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("Device ready", substring = true)
        composeTestRule.onNodeWithText("Review pending devices").performClick()
        waitFor("Pending device (", substring = true)
        composeTestRule.onNodeWithText("Approve").performClick()
        waitFor("only possible from an active device", substring = true)
    }

    @Test
    fun recovery_leavingScreen_dropsCode() {
        api.listHandler = { throw EnrollException.RecoveryRequired() }
        launch()
        composeTestRule.onNodeWithText("Set up this device").performClick()
        waitFor("needs recovery", substring = true)
        composeTestRule.onNodeWithText("Recovery code").performTextInput("SENTINEL-UI-8")
        composeTestRule.onNodeWithText("Back").performScrollTo()
        composeTestRule.onNodeWithText("Back").performClick()
        composeTestRule.onNodeWithText("SENTINEL-UI-8").assertDoesNotExist()
        val stored = FileDeviceMetadataStore.rawFile(context).readBytes()
        assertFalse(String(stored, Charsets.UTF_8).contains("SENTINEL-UI-8"))
    }
}
