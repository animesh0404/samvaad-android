package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.FileDeviceMetadataStore
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 10 persistence/shape tests: bind-adopted records with no handles
 * round-trip, legacy full-handle files still parse, and sentinel recovery
 * codes never appear in the metadata file.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class Slice10PersistenceTest {

    private lateinit var context: Context
    private lateinit var store: FileDeviceMetadataStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        store = FileDeviceMetadataStore(context)
    }

    private fun bindAdopted() = AdoptedDevice(
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

    @Test
    fun bindAdopted_withoutHandles_roundTrips() {
        store.writeAdopted(bindAdopted())
        val read = store.readAdopted()!!
        assertEquals(bindAdopted(), read)
        assertFalse(read.hasLocalKeys)
    }

    @Test
    fun legacyAdopted_withAllHandles_stillParses() {
        // Pre-Slice-10 file shape (all handle fields present): must parse
        // exactly as before — the nullable migration is backward compatible.
        val raw = JSONObject()
            .put("schemaVersion", 1)
            .put("deviceId", "55555555-2222-3333-4444-555555555555")
            .put("signalDeviceId", 1)
            .put("registrationId", 4242)
            .put("identityPublicKeyB64", "aWRlbnRpdHk=")
            .put("signedPrekeyId", 1)
            .put("kyberPrekeyId", 1)
            .put("otpkHighWaterMark", 100)
            .put("roleHint", "PRIMARY")
            .put("statusHint", "ACTIVE")
            .put("identityHandleId", "11111111-2222-3333-4444-555555555555")
            .put("signedHandleId", "22222222-2222-3333-4444-555555555555")
            .put("kyberHandleId", "33333333-2222-3333-4444-555555555555")
            .put("otpkHandleIds", "44444444-2222-3333-4444-555555555555")
            .put("codesAcknowledged", false)
        FileDeviceMetadataStore.rawFile(context).apply {
            parentFile?.mkdirs()
            writeText(JSONObject().put("adopted", raw).toString(), Charsets.UTF_8)
        }
        val read = store.readAdopted()!!
        assertEquals("11111111-2222-3333-4444-555555555555", read.identityHandleId)
        assertEquals(1, read.kyberPrekeyId)
        assertTrue(read.hasLocalKeys)
    }

    @Test
    fun hasLocalKeys_requiresEveryHandle() {
        val full = bindAdopted().copy(
            identityHandleId = "11111111-2222-3333-4444-555555555555",
            signedHandleId = "22222222-2222-3333-4444-555555555555",
            kyberHandleId = "33333333-2222-3333-4444-555555555555",
            otpkHandleIds = listOf("44444444-2222-3333-4444-555555555555"),
        )
        assertTrue(full.hasLocalKeys)
        assertFalse(full.copy(identityHandleId = null).hasLocalKeys)
        assertFalse(full.copy(signedHandleId = null).hasLocalKeys)
        assertFalse(full.copy(kyberHandleId = null).hasLocalKeys)
        assertFalse(full.copy(otpkHandleIds = emptyList()).hasLocalKeys)
    }

    @Test
    fun metadataFile_neverCarriesRecoveryCodes() {
        store.writeAdopted(bindAdopted())
        val text = String(
            FileDeviceMetadataStore.rawFile(context).readBytes(), Charsets.UTF_8
        )
        assertTrue(text.contains("cccccccc-2222-3333-4444-555555555555"))
        assertFalse(text.contains("recoveryCode"))
        assertFalse(text.contains("SENTINEL"))
    }

    @Test
    fun missingHandleKeys_parseAsAbsent_notEmpty() {
        // A record that predates explicit nulls (keys simply absent) must
        // read as handle-less, never as empty-string handles.
        val raw = JSONObject()
            .put("schemaVersion", 1)
            .put("deviceId", "cccccccc-2222-3333-4444-555555555555")
            .put("signalDeviceId", 1)
            .put("registrationId", 5150)
            .put("identityPublicKeyB64", "c2VydmVyLWtleQ==")
            .put("signedPrekeyId", 9)
            .put("otpkHighWaterMark", 0)
            .put("roleHint", "PRIMARY")
            .put("statusHint", "ACTIVE")
            .put("otpkHandleIds", "")
            .put("codesAcknowledged", true)
        FileDeviceMetadataStore.rawFile(context).apply {
            parentFile?.mkdirs()
            writeText(JSONObject().put("adopted", raw).toString(), Charsets.UTF_8)
        }
        val read = store.readAdopted()!!
        assertNull(read.identityHandleId)
        assertNull(read.signedHandleId)
        assertNull(read.kyberHandleId)
        assertNull(read.kyberPrekeyId)
        assertFalse(read.hasLocalKeys)
    }
}
