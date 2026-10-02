package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.DeviceList
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
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
 * Recovery-codes UI handoff: fake-API bootstrap driven through the real
 * [HomeScreen] wiring — codes display, ack control, transition to Done,
 * persisted ack flag. Coordinator ack semantics are covered by unit
 * tests; this covers the Compose handoff only. Codes are never persisted.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class RecoveryCodesFlowTest {

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

    private class FakeApi(val codes: List<String>) : E2eeDeviceApi {
        override suspend fun enroll(
            session: AuthSession,
            serverAddress: String,
            request: EnrollRequest,
        ): EnrollResult = EnrollResult(
            device = DeviceRecord(
                deviceId = "22222222-2222-3333-4444-555555555555",
                registrationId = request.registrationId,
                signalDeviceId = 1,
                deviceIdentityPublicKey = request.deviceIdentityPublicKey,
                signedPrekeyId = request.signedPrekeyId,
                deviceRole = "PRIMARY",
                status = "ACTIVE",
                availablePrekeys = 0,
            ),
            enrollmentState = "NEVER_ENROLLED",
            recoveryCodes = codes,
        )

        override suspend fun uploadOneTimePrekeys(
            session: AuthSession,
            serverAddress: String,
            deviceId: String,
            batch: List<OneTimePrekeyUpload>,
        ) = Unit

        override suspend fun listDevices(
            session: AuthSession,
            serverAddress: String,
        ): DeviceList = DeviceList("ENROLLED_ACTIVE", emptyList())

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
    }

    private lateinit var context: Context
    private lateinit var metadata: FileDeviceMetadataStore

    private val session = AuthSession(
        identifier = "alice",
        accessToken = "access-test-token",
        refreshToken = "refresh-test-token",
        sessionId = "11111111-2222-3333-4444-555555555555",
    )
    private val codes = List(25) { i -> "flow-code-$i" }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        metadata = FileDeviceMetadataStore(context)
    }

    @Test
    fun codesFlow_display_ack_persistsFlag_withoutPersistingCodes() {
        val coordinator = EnrollmentCoordinator(
            api = FakeApi(codes),
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

        composeTestRule.onNodeWithText("Set up this device").performClick()
        // Bounded wait for the async bootstrap (real crypto) to reach codes.
        composeTestRule.waitUntil(60_000) {
            try {
                composeTestRule.onNodeWithText("Save your recovery codes")
                    .fetchSemanticsNode()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        // Codes displayed, ack control present.
        composeTestRule.onNodeWithText("1. flow-code-0", substring = true)
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("I have saved these codes")
            .performScrollTo()
        composeTestRule.onNodeWithText("I have saved these codes").performClick()

        // Transitioned to completed state with the ack recorded.
        composeTestRule.waitUntil(10_000) {
            try {
                composeTestRule.onNodeWithText("Device ready", substring = true)
                    .fetchSemanticsNode()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        assertTrue(metadata.readAdopted()!!.codesAcknowledged)
        // Codes themselves never touch durable storage.
        val stored = FileDeviceMetadataStore.rawFile(context).readBytes()
        codes.forEach {
            assertFalse(String(stored, Charsets.UTF_8).contains(it))
        }
        assertEquals(25, codes.size)
    }
}
