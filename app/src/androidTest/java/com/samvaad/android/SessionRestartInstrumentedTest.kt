package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.session.PersistedSession
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Force-stop / reboot survival for the session record, in two phases
 * driven from the host (mirrors the vault restart tests):
 *
 * 1. `sealPhase` — persist a bundle, record expectations in the cache dir.
 * 2. Host runs `adb shell am force-stop` (and optionally `adb reboot`).
 * 3. `recoverPhase` — fresh process: load and compare.
 *
 * Each phase is launched individually via
 * `-Pandroid.testInstrumentationRunnerArguments.class=...#method`.
 * Phase files hold public metadata only (no tokens).
 */
@RunWith(AndroidJUnit4::class)
class SessionRestartInstrumentedTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun store() =
        FileSessionStore(context, AndroidKeystoreKeyProvider())

    private fun phaseFile(): File = File(context.cacheDir, "session-restart-phase.txt")

    @Test
    fun sealPhase() {
        phaseFile().delete()
        File(context.noBackupFilesDir, FileSessionStore.SUBDIR).deleteRecursively()
        store().save(
            PersistedSession(
                serverAddress = "https://example.test:8080",
                identifier = "alice",
                refreshToken = "restart-persisted-token",
                sessionId = "11111111-2222-3333-4444-555555555555",
                refreshExpiresAtEpochMillis = System.currentTimeMillis() + 86_400_000,
            )
        )
        phaseFile().writeText(
            listOf(
                "serverAddress=https://example.test:8080",
                "identifier=alice",
                "sessionId=11111111-2222-3333-4444-555555555555",
            ).joinToString("\n")
        )
        assertTrue(phaseFile().isFile)
    }

    @Test
    fun recoverPhase() {
        val lines = try {
            phaseFile().readLines()
        } catch (_: Exception) {
            throw AssertionError("phase file absent: run sealPhase first")
        }
        fun value(key: String): String =
            lines.first { it.startsWith("$key=") }.substringAfter("=")

        // Fresh process, fresh instances: only files + Keystore persist.
        val loaded = FileSessionStore(context, AndroidKeystoreKeyProvider()).load()
            ?: throw AssertionError("session record did not survive restart")
        assertEquals(value("serverAddress"), loaded.serverAddress)
        assertEquals(value("identifier"), loaded.identifier)
        assertEquals(value("sessionId"), loaded.sessionId)
        // The token itself survived too (compared against a second read,
        // never printed).
        val again = FileSessionStore(context, AndroidKeystoreKeyProvider()).load()!!
        assertEquals(loaded.refreshToken, again.refreshToken)

        FileSessionStore(context, AndroidKeystoreKeyProvider()).clear()
        phaseFile().delete()
        assertTrue(!phaseFile().exists())
    }
}
