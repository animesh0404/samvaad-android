package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.EnrollmentAttempt
import com.samvaad.android.enroll.FileDeviceMetadataStore
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Device metadata store: round-trip, schema gate, corrupt tolerance, non-secret scan. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class DeviceMetadataStoreTest {

    private lateinit var context: Context
    private lateinit var store: FileDeviceMetadataStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        store = FileDeviceMetadataStore(context)
    }

    private fun attempt() = EnrollmentAttempt(
        identityPublicKeyB64 = "aWRlbnRpdHk=",
        registrationId = 4242,
        signedPrekeyId = 1,
        kyberPrekeyId = 1,
        otpkIds = listOf(1, 2, 3),
        identityHandleId = "11111111-2222-3333-4444-555555555555",
        signedHandleId = "22222222-2222-3333-4444-555555555555",
        kyberHandleId = "33333333-2222-3333-4444-555555555555",
        otpkHandleIds = listOf("44444444-2222-3333-4444-555555555555"),
    )

    private fun adopted() = AdoptedDevice(
        deviceId = "55555555-2222-3333-4444-555555555555",
        signalDeviceId = 1,
        registrationId = 4242,
        identityPublicKeyB64 = "aWRlbnRpdHk=",
        signedPrekeyId = 1,
        kyberPrekeyId = 1,
        otpkHighWaterMark = 100,
        roleHint = "PRIMARY",
        statusHint = "ACTIVE",
        identityHandleId = "11111111-2222-3333-4444-555555555555",
        signedHandleId = "22222222-2222-3333-4444-555555555555",
        kyberHandleId = "33333333-2222-3333-4444-555555555555",
        otpkHandleIds = List(100) { "66666666-2222-3333-4444-5555555555%02d".format(it) },
        codesAcknowledged = false,
    )

    @Test
    fun roundTrip_attemptAndAdopted() {
        assertNull(store.readAttempt())
        assertNull(store.readAdopted())
        store.writeAttempt(attempt())
        store.writeAdopted(adopted())
        assertEquals(attempt(), store.readAttempt())
        assertEquals(adopted(), store.readAdopted())
        store.clearAttempt()
        assertNull(store.readAttempt())
        assertEquals(adopted(), store.readAdopted())
        store.clearAdopted()
        assertNull(store.readAdopted())
    }

    @Test
    fun corruptFile_readsAsAbsent() {
        FileDeviceMetadataStore.rawFile(context).apply {
            parentFile?.mkdirs()
            writeText("{not json", Charsets.UTF_8)
        }
        assertNull(store.readAttempt())
        assertNull(store.readAdopted())
    }

    @Test
    fun unknownSchema_rejected() {
        FileDeviceMetadataStore.rawFile(context).apply {
            parentFile?.mkdirs()
            writeText(
                """{"attempt":{"schemaVersion":999,"identityPublicKeyB64":"eA=="}}""",
                Charsets.UTF_8
            )
        }
        assertNull(store.readAttempt())
    }

    @Test
    fun storedBytes_containNoSecrets() {
        store.writeAttempt(attempt())
        store.writeAdopted(adopted())
        val bytes = FileDeviceMetadataStore.rawFile(context).readBytes()
        val text = String(bytes, Charsets.UTF_8)
        // Non-secret by construction: no tokens, codes, or private material
        // ever enter this store; assert the shape holds.
        assertTrue(text.contains("identityPublicKeyB64"))
        assertTrue(!text.contains("accessToken"))
        assertTrue(!text.contains("refreshToken"))
        assertTrue(!text.contains("recoveryCode"))
    }
}
