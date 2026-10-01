package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import java.io.File
import java.util.Base64
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Process-death simulation in two phases, driven from the host:
 *
 * 1. `sealPhase` — generate, seal, persist ONLY handle UUIDs + the public
 *    identity bytes (public, safe) to a phase file in the cache dir.
 * 2. Host runs `adb shell am force-stop com.samvaad.android` (and
 *    optionally `adb reboot`).
 * 3. `recoverPhase` — fresh process: unseal, restore, re-verify.
 *
 * Each phase is launched individually via
 * `-Pandroid.testInstrumentationRunnerArguments.class=...#method`.
 * No key material ever touches the phase file.
 */
@RunWith(AndroidJUnit4::class)
class CryptoVaultRestartInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun vault() =
        AndroidCryptoVault(context, AndroidKeystoreKeyProvider())

    private fun phaseFile(): File = File(context.cacheDir, "vault-restart-phase.txt")

    @Test
    fun sealPhase() {
        phaseFile().delete()
        val adapter = AndroidSignalAdapter()
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, 2201)
        val v = vault()
        v.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        v.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))

        val lines = listOf(
            "${CryptoRecordKind.IDENTITY.name}:${identity.privateHandle.id}",
            "${CryptoRecordKind.SIGNED_PREKEY.name}:${signed.privateHandle.id}",
            "EXPECTED_IDENTITY_B64:" + Base64.getEncoder().encodeToString(identity.publicKey),
        )
        phaseFile().writeText(lines.joinToString("\n"))
        assertTrue(phaseFile().isFile)
    }

    @Test
    fun recoverPhase() {
        val lines = try {
            phaseFile().readLines()
        } catch (_: Exception) {
            throw AssertionError("phase file absent: run sealPhase first")
        }
        fun uuidFor(kind: CryptoRecordKind): UUID {
            val line = lines.first { it.startsWith(kind.name + ":") }
            return UUID.fromString(line.substringAfter(":"))
        }
        val expectedIdentity =
            Base64.getDecoder().decode(lines.first { it.startsWith("EXPECTED_IDENTITY_B64:") }.substringAfter(":"))

        // Fresh process, fresh instances: only files + Keystore persist.
        val freshVault = vault()
        val freshAdapter = AndroidSignalAdapter()
        val idHandle = com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle(
            uuidFor(CryptoRecordKind.IDENTITY), CryptoRecordKind.IDENTITY
        )
        val signedHandle = com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle(
            uuidFor(CryptoRecordKind.SIGNED_PREKEY), CryptoRecordKind.SIGNED_PREKEY
        )

        val idBack = freshAdapter.restoreRecord(
            idHandle, freshVault.unseal(idHandle, CryptoRecordKind.IDENTITY)
        ) as AndroidSignalAdapter.RestoredPublic.Identity
        assertArrayEquals(expectedIdentity, idBack.value.publicKey)

        val signedBack = freshAdapter.restoreRecord(
            signedHandle, freshVault.unseal(signedHandle, CryptoRecordKind.SIGNED_PREKEY)
        ) as AndroidSignalAdapter.RestoredPublic.Signed
        assertEquals(2201, signedBack.value.prekeyId)
        assertTrue(
            freshAdapter.verifySignedPrekey(
                idBack.value.publicKey, signedBack.value.publicKey, signedBack.value.signature
            )
        )

        // Cleanup: remove test records and the phase file.
        freshVault.delete(idHandle, CryptoRecordKind.IDENTITY)
        freshVault.delete(signedHandle, CryptoRecordKind.SIGNED_PREKEY)
        phaseFile().delete()
        assertTrue(!phaseFile().exists())
    }
}
