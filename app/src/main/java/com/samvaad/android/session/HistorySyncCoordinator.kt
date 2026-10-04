package com.samvaad.android.session

import com.samvaad.android.AuthSession
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecoveryException
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.SessionCryptoException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.highestContiguous
import com.samvaad.android.enroll.DeviceMetadataStore
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.SyncBatchItem
import com.samvaad.android.enroll.SyncUploadRequest
import java.io.IOException
import java.util.UUID
import kotlinx.coroutines.CancellationException

/**
 * Bounded history-sync bounds. Small and fixed like [SweepBounds]: a
 * manual sync must finish quickly and never schedule itself.
 */
data class SyncBounds(
    /** Conversations touched per sync run (sorted order, Primary + Companion). */
    val maxConversationsPerSync: Int = 5,
    /** History items exported per conversation per sync run (Primary). */
    val maxItemsPerConversation: Int = 100,
    /** Fetch page size per request (Companion). */
    val fetchPageSize: Int = 20,
    /** Fetch pages per conversation per sync run (Companion). */
    val fetchMaxPages: Int = 5,
)

/** Headless history-sync outcome. Fixed safe shape only, no server text. */
data class HistorySyncReport(
    val exportedItems: Int,
    val importedStored: Int,
    val importedDuplicates: Int,
    val importedSkipped: Int,
    val conversationsCompleted: Int,
    /** First failure encountered, if any; remaining work still attempted. */
    val error: String?,
)

/**
 * Manual Primary-to-Companion history synchronization (Slice 12).
 *
 * Role-gated by live server device state: ACTIVE PRIMARY exports its
 * durable Room history (re-encrypted per Companion), ACTIVE COMPANION
 * imports into its own Room. No push, no polling, no background work,
 * no per-Companion jobs: export is blind and idempotent (server
 * dedupes), import is range-pulled and prefix-acked. Shares
 * [deviceLocks] with messaging so the P→C Signal session never races
 * normal traffic; shares the inbox decrypt/seal pipeline through
 * [InboxProcessor.ingestSyncItem].
 *
 * Construction is explicit; no DI.
 */
class HistorySyncCoordinator(
    private val api: E2eeDeviceApi,
    private val localMetadata: DeviceMetadataStore,
    private val sessions: SessionMetadataStore,
    private val adapter: AndroidSignalAdapter,
    private val identityVault: AndroidCryptoVault,
    private val sessionVault: AndroidCryptoVault,
    private val establisher: SessionEstablisher,
    private val deviceLocks: SessionDeviceLocks,
    private val db: MessageDatabase,
    private val contentSealer: MessageContentSealer,
    private val syncMetadata: SyncMetadataStore,
    private val bounds: SyncBounds = SyncBounds(),
) {
    private val inbox = InboxProcessor(
        api = api,
        localMetadata = localMetadata,
        sessions = sessions,
        adapter = adapter,
        cryptoVault = identityVault,
        sessionVault = sessionVault,
        deviceLocks = deviceLocks,
        db = db,
        contentSealer = contentSealer,
    )

    private fun dao() = db.messageDao()

    suspend fun sync(
        session: AuthSession,
        serverAddress: String,
        identifier: String,
    ): HistorySyncReport {
        // Devices with no sync role (no adopted record, unknown device,
        // inactive, or a role other than PRIMARY/COMPANION) are a silent
        // no-op: history sync simply does not apply to them, and manual
        // Sync must not gain new errors for existing flows. Errors
        // surface only when a participating device's sync actually fails.
        val adopted = try {
            localMetadata.readAdopted()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return HistorySyncReport(0, 0, 0, 0, 0, null)
        } ?: return HistorySyncReport(0, 0, 0, 0, 0, null)
        val devices = try {
            api.listDevices(session, serverAddress).devices
        } catch (e: CancellationException) {
            throw e
        } catch (_: EnrollException.Transport) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_UNREACHABLE)
        } catch (_: EnrollException) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_REJECTED)
        } catch (_: IOException) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_UNREACHABLE)
        }
        val mine = devices.firstOrNull { it.deviceId == adopted.deviceId }
            ?: return HistorySyncReport(0, 0, 0, 0, 0, null)
        if (mine.status != ACTIVE_STATUS) {
            return HistorySyncReport(0, 0, 0, 0, 0, null)
        }
        return when (mine.deviceRole) {
            PRIMARY_ROLE -> exportAll(session, serverAddress, identifier, adopted.deviceId, devices
                .filter { it.deviceRole == COMPANION_ROLE && it.status == ACTIVE_STATUS }
                .map { it.deviceId }
                .filter { it != adopted.deviceId })
            COMPANION_ROLE -> importAll(session, serverAddress, identifier, devices)
            else -> HistorySyncReport(0, 0, 0, 0, 0, null)
        }
    }

    // ---- Primary export ----

    private suspend fun exportAll(
        session: AuthSession,
        serverAddress: String,
        identifier: String,
        localDeviceId: String,
        companions: List<String>,
    ): HistorySyncReport {
        if (companions.isEmpty()) return HistorySyncReport(0, 0, 0, 0, 0, null)
        var exported = 0
        var completed = 0
        var error: String? = null
        val conversations = try {
            dao().knownConversationIds().sorted()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_STORE_ERROR)
        }.take(bounds.maxConversationsPerSync)
        for (conversationId in conversations) {
            for (companionId in companions) {
                val outcome = try {
                    exportConversation(
                        session, serverAddress, identifier,
                        localDeviceId, companionId, conversationId,
                    )
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    ExportOutcome(0, SYNC_UNREACHABLE)
                }
                exported += outcome.exported
                if (outcome.error != null && error == null) error = outcome.error
            }
            completed++
        }
        return HistorySyncReport(exported, 0, 0, 0, completed, error)
    }

    private data class ExportOutcome(val exported: Int, val error: String?)

    private suspend fun exportConversation(
        session: AuthSession,
        serverAddress: String,
        identifier: String,
        localDeviceId: String,
        companionId: String,
        conversationId: String,
    ): ExportOutcome {
        val established = try {
            establisher.establish(session, serverAddress, identifier, companionId)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return ExportOutcome(0, SYNC_UNREACHABLE)
        }
        if (established !is SessionEstablishResult.Established) {
            return ExportOutcome(0, SYNC_SESSION_ERROR)
        }
        val sequences = try {
            dao().sequencesFor(conversationId)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return ExportOutcome(0, SYNC_STORE_ERROR)
        }
        val frontier = highestContiguous(sequences)
        if (frontier == 0L) return ExportOutcome(0, null)
        var exported = 0
        var after = 0L
        while (exported < bounds.maxItemsPerConversation) {
            val rows = try {
                dao().historyPage(conversationId, after, bounds.fetchPageSize)
                    .filter { it.sequenceNumber <= frontier }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return ExportOutcome(exported, SYNC_STORE_ERROR)
            }
            if (rows.isEmpty()) break
            val items = mutableListOf<SyncBatchItem>()
            for (row in rows) {
                val sealed = row.plaintextSealed
                    ?: return ExportOutcome(exported, SYNC_CONTENT_ERROR)
                val plaintext = try {
                    contentSealer.open(row.messageId, sealed)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    return ExportOutcome(exported, SYNC_CONTENT_ERROR)
                }
                val payload = try {
                    buildSyncPayload(
                        conversationId = row.conversationId,
                        messageId = row.messageId,
                        sequenceNumber = row.sequenceNumber,
                        senderDeviceId = row.senderDeviceId,
                        recipientDeviceId = row.recipientDeviceId,
                        serverTimestamp = row.serverTimestamp,
                        plaintext = plaintext,
                        frontier = frontier,
                    )
                } catch (_: IllegalArgumentException) {
                    return ExportOutcome(exported, SYNC_CONTENT_ERROR)
                }
                val encrypted = encryptForSync(
                    session, localDeviceId, identifier, companionId, payload
                ) ?: return ExportOutcome(exported, SYNC_SESSION_ERROR)
                items.add(
                    SyncBatchItem(
                        messageId = row.messageId,
                        conversationId = row.conversationId,
                        sequenceNumber = row.sequenceNumber,
                        senderDeviceId = localDeviceId,
                        envelopeType = encrypted.envelopeType,
                        ciphertextBase64 = SpikeCryptoMaterial.encodeBase64(encrypted.ciphertext),
                    )
                )
                if (exported + items.size >= bounds.maxItemsPerConversation) break
            }
            if (items.isEmpty()) break
            // Same batch id on immediate transport retry: the server
            // absorbs identical repeats through the stored receipt.
            // Rejections (conflict/forbidden) surface, never retried.
            val batchId = UUID.randomUUID()
            val request = SyncUploadRequest(
                syncBatchId = batchId,
                recipientDeviceId = companionId,
                conversationId = conversationId,
                fromSequence = after,
                frontier = frontier,
                items = items,
            )
            val first = uploadOnce(session, serverAddress, request)
            val outcome = when (first) {
                is UploadAttempt.Uploaded -> first.count
                is UploadAttempt.Rejected -> return ExportOutcome(exported, first.error)
                is UploadAttempt.Retryable -> when (val second = uploadOnce(session, serverAddress, request)) {
                    is UploadAttempt.Uploaded -> second.count
                    is UploadAttempt.Rejected -> return ExportOutcome(exported, second.error)
                    is UploadAttempt.Retryable -> return ExportOutcome(exported, SYNC_UNREACHABLE)
                }
            }
            exported += outcome
            after = items.maxOf { it.sequenceNumber }
            if (rows.size < bounds.fetchPageSize) break
        }
        return ExportOutcome(exported, null)
    }

    /**
     * One upload attempt: uploaded count on success, null on transport
     * failure (caller may retry identically once), fail-closed string
     * on rejection (conflict/forbidden surface, never blind-retried).
     */
    private sealed interface UploadAttempt {
        data class Uploaded(val count: Int) : UploadAttempt
        data object Retryable : UploadAttempt
        data class Rejected(val error: String) : UploadAttempt
    }

    private suspend fun uploadOnce(
        session: AuthSession,
        serverAddress: String,
        request: SyncUploadRequest,
    ): UploadAttempt {
        return try {
            val result = api.uploadSyncBatch(session, serverAddress, request)
            UploadAttempt.Uploaded(result.acceptedCount)
        } catch (e: CancellationException) {
            throw e
        } catch (_: EnrollException.Transport) {
            UploadAttempt.Retryable
        } catch (_: EnrollException) {
            UploadAttempt.Rejected(SYNC_REJECTED)
        } catch (_: IOException) {
            UploadAttempt.Retryable
        }
    }

    /**
     * Encrypts one sync payload into the established P→C session and
     * persists the advanced session, mirroring the send-path ordering
     * (encrypt → seal session → upload). Null on any crypto failure:
     * the conversation export stops fail-closed.
     */
    private suspend fun encryptForSync(
        session: AuthSession,
        localDeviceId: String,
        identifier: String,
        companionId: String,
        payload: ByteArray,
    ): EncryptedSyncItem? {
        return deviceLocks.withDeviceLock(companionId) {
            val adopted = try {
                localMetadata.readAdopted()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return@withDeviceLock null
            } ?: return@withDeviceLock null
            val identityHandleId = adopted.identityHandleId ?: return@withDeviceLock null
            val localIdentity = try {
                val handle = SpikeCryptoMaterial.SealedHandle(
                    java.util.UUID.fromString(identityHandleId),
                    com.samvaad.android.crypto.CryptoRecordKind.IDENTITY,
                )
                val bytes = identityVault.unseal(handle,
                    com.samvaad.android.crypto.CryptoRecordKind.IDENTITY)
                when (val restored = adapter.restoreRecord(handle, bytes)) {
                    is AndroidSignalAdapter.RestoredPublic.Identity -> restored.value
                    else -> return@withDeviceLock null
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return@withDeviceLock null
            }
            val entry = try {
                sessions.read(companionId)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return@withDeviceLock null
            } ?: return@withDeviceLock null
            val pinned = try {
                SpikeCryptoMaterial.decodeBase64(entry.remoteIdentityPublicKeyB64)
            } catch (_: IllegalArgumentException) {
                return@withDeviceLock null
            }
            val sealed = try {
                sessionVault.unseal(
                    SessionEstablisher.sessionHandleFor(companionId),
                    com.samvaad.android.crypto.CryptoRecordKind.SESSION,
                )
            } catch (_: Exception) {
                return@withDeviceLock null
            }
            try {
                val ready = adapter.inspectSession(sealed)
                if (!ready.remoteIdentityBytes.contentEquals(pinned)) return@withDeviceLock null
            } catch (_: SessionCryptoException) {
                return@withDeviceLock null
            }
            val encrypted = try {
                adapter.encryptForSubmit(
                    localIdentity = localIdentity,
                    localRegistrationId = adopted.registrationId,
                    sessionBytes = sealed,
                    pinnedRemoteIdentity = pinned,
                    remoteUsername = identifier,
                    remoteSignalDeviceId = entry.remoteSignalDeviceId,
                    plaintext = payload,
                )
            } catch (_: SessionCryptoException) {
                return@withDeviceLock null
            }
            try {
                sessionVault.seal(
                    SessionEstablisher.sessionHandleFor(companionId),
                    com.samvaad.android.crypto.CryptoRecordKind.SESSION,
                    encrypted.postEncryptSessionBytes,
                )
            } catch (_: Exception) {
                return@withDeviceLock null
            }
            EncryptedSyncItem(
                envelopeType = encrypted.envelopeType,
                ciphertext = encrypted.ciphertextBytes,
            )
        }
    }

    private data class EncryptedSyncItem(val envelopeType: String, val ciphertext: ByteArray)

    // ---- Companion import ----

    private suspend fun importAll(
        session: AuthSession,
        serverAddress: String,
        identifier: String,
        devices: List<com.samvaad.android.enroll.DeviceRecord>,
    ): HistorySyncReport {
        val primary = devices.firstOrNull {
            it.deviceRole == PRIMARY_ROLE && it.status == ACTIVE_STATUS
        } ?: return HistorySyncReport(0, 0, 0, 0, 0, SYNC_NO_PRIMARY)
        val established = try {
            establisher.establish(session, serverAddress, identifier, primary.deviceId)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_UNREACHABLE)
        }
        if (established !is SessionEstablishResult.Established) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_SESSION_ERROR)
        }
        var stored = 0
        var duplicates = 0
        var skipped = 0
        var completed = 0
        var error: String? = null
        // Union local rows with the server conversation list: a fresh
        // Companion holds no local rows yet, so local IDs alone would
        // leave it permanently empty. Both sources are plain
        // identifiers; content still arrives only through sync fetch.
        val localIds = try {
            dao().knownConversationIds()
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_STORE_ERROR)
        }
        val serverIds = try {
            api.listConversations(session, serverAddress)
        } catch (e: CancellationException) {
            throw e
        } catch (_: EnrollException.Transport) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_UNREACHABLE)
        } catch (_: EnrollException) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_REJECTED)
        } catch (_: IOException) {
            return HistorySyncReport(0, 0, 0, 0, 0, SYNC_UNREACHABLE)
        }
        val conversations = (localIds + serverIds).toSortedSet().take(bounds.maxConversationsPerSync)
        for (conversationId in conversations) {
            val outcome = try {
                importConversation(session, serverAddress, primary.deviceId, conversationId)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                ImportOutcome(0, 0, 0, SYNC_UNREACHABLE)
            }
            stored += outcome.stored
            duplicates += outcome.duplicates
            skipped += outcome.skipped
            if (outcome.error != null && error == null) error = outcome.error
            completed++
        }
        return HistorySyncReport(0, stored, duplicates, skipped, completed, error)
    }

    private data class ImportOutcome(
        val stored: Int,
        val duplicates: Int,
        val skipped: Int,
        val error: String?,
    )

    private suspend fun importConversation(
        session: AuthSession,
        serverAddress: String,
        primaryDeviceId: String,
        conversationId: String,
    ): ImportOutcome {
        var stored = 0
        var duplicates = 0
        var skipped = 0
        var pages = 0
        while (pages < bounds.fetchMaxPages) {
            val contiguous = try {
                highestContiguous(dao().sequencesFor(conversationId))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                return ImportOutcome(stored, duplicates, skipped, SYNC_STORE_ERROR)
            }
            val items = try {
                api.fetchSyncBatch(
                    session, serverAddress, conversationId, contiguous, bounds.fetchPageSize
                )
            } catch (e: CancellationException) {
                throw e
            } catch (_: EnrollException.Transport) {
                return ImportOutcome(stored, duplicates, skipped, SYNC_UNREACHABLE)
            } catch (_: EnrollException) {
                return ImportOutcome(stored, duplicates, skipped, SYNC_REJECTED)
            } catch (_: IOException) {
                return ImportOutcome(stored, duplicates, skipped, SYNC_UNREACHABLE)
            }
            if (items.isEmpty()) break
            for (item in items) {
                when (val ingested = ingestSyncItemSafe(item, primaryDeviceId, conversationId)) {
                    is InboxProcessor.SyncIngestResult.Stored -> {
                        stored++
                        recordFrontier(conversationId, ingested.frontier)?.let { anomaly ->
                            return ImportOutcome(stored, duplicates, skipped, anomaly)
                        }
                    }
                    is InboxProcessor.SyncIngestResult.Duplicate -> duplicates++
                    is InboxProcessor.SyncIngestResult.Skipped -> skipped++
                }
            }
            pages++
            if (items.size < bounds.fetchPageSize) break
        }
        val contiguous = try {
            highestContiguous(dao().sequencesFor(conversationId))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return ImportOutcome(stored, duplicates, skipped, SYNC_STORE_ERROR)
        }
        // ACK the durable contiguous prefix (even when nothing new was
        // stored: a crash after persistence but before ACK converges
        // here through duplicate-safe ingest plus ACK).
        if (contiguous > 0) {
            try {
                api.ackSync(session, serverAddress, conversationId, contiguous)
            } catch (e: CancellationException) {
                throw e
            } catch (_: EnrollException.Transport) {
                return ImportOutcome(stored, duplicates, skipped, SYNC_UNREACHABLE)
            } catch (_: EnrollException) {
                return ImportOutcome(stored, duplicates, skipped, SYNC_REJECTED)
            } catch (_: IOException) {
                return ImportOutcome(stored, duplicates, skipped, SYNC_UNREACHABLE)
            }
        }
        return ImportOutcome(stored, duplicates, skipped, null)
    }

    private suspend fun ingestSyncItemSafe(
        item: com.samvaad.android.enroll.SyncBatchItem,
        primaryDeviceId: String,
        conversationId: String,
    ): InboxProcessor.SyncIngestResult {
        // Wire-level conversation guard before any crypto: the server
        // must only return this conversation's rows.
        if (item.conversationId != conversationId) {
            return InboxProcessor.SyncIngestResult.Skipped("sync-conversation-mismatch")
        }
        return try {
            inbox.ingestSyncItem(item, primaryDeviceId)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            InboxProcessor.SyncIngestResult.Skipped("sync-ingest-failed")
        }
    }

    /**
     * Records an authenticated frontier, returning an anomaly message
     * when the new value regresses below a previously stored one.
     * Regressions are surfaced, never silently accepted; the durable
     * rows that produced them stay intact.
     */
    private suspend fun recordFrontier(conversationId: String, frontier: Long): String? {
        return try {
            val previous = syncMetadata.readFrontier(conversationId)
            if (previous != null && frontier < previous) {
                return SYNC_FRONTIER_ANOMALY
            }
            if (previous == null || frontier > previous) {
                syncMetadata.writeFrontier(conversationId, frontier)
            }
            null
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            SYNC_STORE_ERROR
        }
    }

    companion object {
        const val PRIMARY_ROLE = "PRIMARY"
        const val COMPANION_ROLE = "COMPANION"
        const val ACTIVE_STATUS = "ACTIVE"
        const val SYNC_UNREACHABLE = "Cannot reach the server. Check the address and try again."
        const val SYNC_STORE_ERROR = "Local history storage is unavailable."
        const val SYNC_SESSION_ERROR = "Secure sync session unavailable."
        const val SYNC_CONTENT_ERROR = "Local history content unavailable."
        const val SYNC_NO_PRIMARY = "No active Primary device found."
        const val SYNC_REJECTED = "History sync was rejected. Check device status and try again."
        const val SYNC_FRONTIER_ANOMALY = "History sync detected inconsistent progress."
    }
}
