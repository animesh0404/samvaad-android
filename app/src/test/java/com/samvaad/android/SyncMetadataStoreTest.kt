package com.samvaad.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.session.FileSyncMetadataStore
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Sync frontier store tests: per-conversation frontier hints persist
 * across instances (restart), unknown conversations read pending-safe
 * null, and a corrupt file fails to null rather than crashing.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SyncMetadataStoreTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, FileSyncMetadataStore.SUBDIR).deleteRecursively()
    }

    @After
    fun tearDown() {
        File(context.noBackupFilesDir, FileSyncMetadataStore.SUBDIR).deleteRecursively()
    }

    @Test
    fun unknownConversation_readsNull() {
        assertNull(FileSyncMetadataStore(context).readFrontier("nope"))
    }

    @Test
    fun writeRead_roundTripsPerConversation() {
        val store = FileSyncMetadataStore(context)
        store.writeFrontier("conv-a", 12L)
        store.writeFrontier("conv-b", 3L)
        assertEquals(12L, store.readFrontier("conv-a"))
        assertEquals(3L, store.readFrontier("conv-b"))
    }

    @Test
    fun overwrite_keepsLatest() {
        val store = FileSyncMetadataStore(context)
        store.writeFrontier("conv-a", 5L)
        store.writeFrontier("conv-a", 9L)
        assertEquals(9L, store.readFrontier("conv-a"))
    }

    @Test
    fun restart_newInstanceSeesStoredFrontier() {
        FileSyncMetadataStore(context).writeFrontier("conv-a", 21L)
        assertEquals(21L, FileSyncMetadataStore(context).readFrontier("conv-a"))
    }

    @Test
    fun corruptFile_readsNull() {
        val dir = File(context.noBackupFilesDir, FileSyncMetadataStore.SUBDIR)
        dir.mkdirs()
        File(dir, FileSyncMetadataStore.FILE_NAME).writeText("{not json", Charsets.UTF_8)
        assertNull(FileSyncMetadataStore(context).readFrontier("conv-a"))
    }
}
