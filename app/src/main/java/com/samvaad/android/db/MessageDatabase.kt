package com.samvaad.android.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import java.io.File

/**
 * Durable message/conversation/cursor facts (slice: durable message
 * state). Version 1, fresh installs only: no migrations exist and none
 * are configured — a future schema change must add an explicit
 * migration, never a destructive fallback (silent data loss would
 * destroy Primary history).
 *
 * Boundary reminder: this database holds message facts plus opaque
 * (`ciphertext`) and sealed (`plaintextSealed`) BLOBs. Private key
 * material, SessionRecords, tokens, and plaintext never enter it —
 * those live in the Keystore vault / sealed session store.
 */
@Database(
    entities = [ConversationEntity::class, MessageEntity::class],
    version = 1,
    exportSchema = false,
)
abstract class MessageDatabase : RoomDatabase() {
    abstract fun messageDao(): MessageDao

    companion object {
        const val SUBDIR = "message-state"
        const val FILE_NAME = "messages.db"

        /**
         * Open (creating on first run) the database file strictly under
         * [Context.getNoBackupFilesDir]: durable message state must never
         * become backup-eligible. No fallback location, no silent
         * recreation — open failure throws and the caller fails closed.
         */
        fun open(context: Context): MessageDatabase {
            val dir = File(context.noBackupFilesDir, SUBDIR)
            if (!dir.isDirectory) dir.mkdirs()
            require(dir.isDirectory) { "message-state directory unavailable" }
            return Room.databaseBuilder(
                context,
                MessageDatabase::class.java,
                File(dir, FILE_NAME).absolutePath,
            ).build()
        }

        /** Test/support hook: the exact database file location. */
        fun file(context: Context): File =
            File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME)
    }
}
