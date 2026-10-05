package com.samvaad.android

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.db.MessageDatabase
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.enroll.ApprovalLoad
import com.samvaad.android.enroll.ApprovalView
import com.samvaad.android.enroll.ApproveOutcome
import com.samvaad.android.enroll.BootstrapFinal
import com.samvaad.android.enroll.BootstrapProgress
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollException
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FailKind
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.HttpE2eeDeviceApi
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.enroll.RecoveryMode
import com.samvaad.android.enroll.SessionBindOutcome
import com.samvaad.android.friends.FriendEntry
import com.samvaad.android.friends.FriendException
import com.samvaad.android.friends.FriendRequestRecord
import com.samvaad.android.friends.FriendsApi
import com.samvaad.android.friends.HttpFriendsApi
import com.samvaad.android.session.FileSessionMetadataStore
import com.samvaad.android.session.FileSyncMetadataStore
import com.samvaad.android.session.HistorySyncCoordinator
import com.samvaad.android.session.InboxProcessor
import com.samvaad.android.session.MessageSender
import com.samvaad.android.session.RealtimeInbox
import com.samvaad.android.session.ReconciliationSweep
import com.samvaad.android.session.SendResult
import com.samvaad.android.session.SessionDeviceLocks
import com.samvaad.android.session.SessionEstablisher
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.SessionMetadataStore
import com.samvaad.android.session.SessionRefresher
import com.samvaad.android.session.SessionStore
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Authenticated surface with first-device bootstrap (Slice: enrollment).
 *
 * Receives the in-memory [AuthSession] and server address from the entry
 * screen — tokens are used for enrollment HTTP only, never persisted,
 * never rendered. The [EnrollmentCoordinator] is constructed explicitly
 * here (no DI framework); orchestration stays out of Compose.
 */
private sealed interface EnrollUiState {
    data object Idle : EnrollUiState
    data class Working(val progress: BootstrapProgress) : EnrollUiState
    data class Codes(val codes: List<String>) : EnrollUiState
    data class Done(val label: String, val codesAcknowledged: Boolean) : EnrollUiState
    data class Failed(val message: String) : EnrollUiState
    data class Blocked(val message: String) : EnrollUiState
    /** Waiting for approval elsewhere: actionable via Check status. */
    data class Pending(val label: String) : EnrollUiState
    /** Adopted row is dead server-side: fresh enrollment only. */
    data class Denied(val label: String) : EnrollUiState
    /**
     * Recovery entry. The code itself lives in a separate transient
     * Compose var (never in this state, never persisted). [devices] is
     * the bind picker once loaded; [error] is the last attempt outcome.
     */
    data class Recovery(
        val devices: List<DeviceRecord>?,
        val error: String?,
        val working: Boolean,
    ) : EnrollUiState
}

private sealed interface ApprovalUi {
    data object Loading : ApprovalUi
    data class Ready(val view: ApprovalView) : ApprovalUi
    data class Failed(val message: String) : ApprovalUi
    data class Approved(val label: String) : ApprovalUi
}

private const val SETUP_FAILED_MESSAGE =
    "Device setup failed. Check the connection and try again."
private const val UNAUTHORIZED_MESSAGE =
    "Your sign-in expired. Sign in again and retry setup."
private const val REJECTED_MESSAGE =
    "The server rejected this device. Contact your administrator."
private const val RECONCILE_MESSAGE =
    "Device setup needs attention before it can continue."
private const val RECOVERY_MESSAGE =
    "This account needs recovery before a new device can join."
private const val PENDING_MESSAGE =
    "This device is waiting for approval from another device."
private const val DENIED_MESSAGE =
    "This device was not approved. You can set it up again as a new device."
private const val RECOVERY_CODE_LABEL = "Recovery code"
private const val RECOVERY_HINT =
    "Enter one recovery code from your set. Codes are single-use and " +
        "are never stored on this device."
private const val RECOVERY_REJECTED_MESSAGE =
    "That recovery code was not accepted. Try another code from your set."
private const val RECOVERY_TRANSPORT_MESSAGE =
    "Recovery could not reach the server. If the attempt went through, " +
        "check status; otherwise try another code."
private const val APPROVAL_DENIED_MESSAGE =
    "Approval is only possible from an active device on this account."
private const val APPROVAL_NONE_MESSAGE = "No devices are waiting for approval."
private const val APPROVAL_INACTIVE_MESSAGE =
    "Approval needs an active device on this installation."
private const val CONVERSATIONS_LOAD_FAILED_MESSAGE =
    "Could not load conversations."
private const val MESSAGES_LOAD_FAILED_MESSAGE =
    "Could not load messages."
private const val SYNC_FAILED_MESSAGE =
    "Sync failed. Check the connection and try again."
private const val BIND_FAILED_MESSAGE =
    "Could not restore this device's session. Check the connection and try Sync again."
private const val BIND_DEVICE_MESSAGE =
    "This device could not be restored on your account. Run device setup again."
private const val NOT_FRIENDS_MESSAGE =
    "You can only message friends."
private const val USER_NOT_FOUND_MESSAGE =
    "User not found. Check the name and try again."
private const val DIRECTORY_FAILED_MESSAGE =
    "Could not load devices. Check the connection and try again."
private const val SEND_FAILED_MESSAGE =
    "Could not send. Check the connection and try again."
private const val FRIENDS_FAILED_MESSAGE =
    "Could not load friends. Check the connection and try again."
private const val ADD_SELF_MESSAGE =
    "You cannot add yourself as a friend."
private const val ALREADY_FRIENDS_MESSAGE =
    "A request is already waiting, or you are already friends."
private const val REQUEST_GONE_MESSAGE =
    "That request is no longer waiting."

/**
 * Slice 11 messaging dependencies. One holder per authenticated screen:
 * exactly ONE [SessionDeviceLocks] is shared by sender, establisher
 * paths, and sweep (the sweep builds its own sender/inbox on the same
 * holder), so SessionRecord mutation stays serialized per remote
 * device. No DI framework; explicit construction in [remember].
 */
private class MessagingGraph(
    val api: E2eeDeviceApi,
    val db: MessageDatabase,
    val sessions: SessionMetadataStore,
    val sealer: MessageContentSealer,
    val sender: MessageSender,
    val establisher: SessionEstablisher,
    val sweep: ReconciliationSweep,
    val historySync: HistorySyncCoordinator,
    /** Separate inbox sharing the graph locks/db: realtime ingest seam. */
    val rtInbox: InboxProcessor,
    /** Foreground-only socket: started after a clean sweep, never alone. */
    val realtime: RealtimeInbox,
)

@Composable
fun HomeScreen(
    identifier: String,
    session: AuthSession,
    serverAddress: String,
    // Test seam: production passes null and gets the real coordinator.
    // Kept as an explicit nullable parameter (no DI framework).
    coordinator: EnrollmentCoordinator? = null,
    authApi: AuthApi = HttpAuthApi(),
    /**
     * Session durability + logout wiring. Null in previews and legacy
     * tests: logout then only leaves the screen, with nothing to wipe.
     */
    sessionStore: SessionStore? = null,
    /**
     * Test seams for the Slice 11 messaging graph. Production passes
     * null: HTTP goes through the real API boundary and the vault/sealer
     * use the Keystore wrapping key.
     */
    deviceApi: E2eeDeviceApi? = null,
    wrappingKeys: WrappingKeyProvider? = null,
    /**
     * Test seam for the Slice 14 friends boundary. Production passes
     * null and gets the real HTTP client. Kept explicit/nullable like
     * the other seams (no DI).
     */
    friendsApi: FriendsApi? = null,
    onLogout: () -> Unit = {},
    /**
     * Test seam for the Slice 13 realtime socket. Production passes null
     * and gets the default WebSocket factory (platform TLS, no custom
     * trust). Kept explicit/nullable like the other seams (no DI).
     */
    realtimeSocketFactory: ((
        java.net.URI,
        RealtimeInbox.SocketEvents,
    ) -> RealtimeInbox.RealtimeSocket)? = null,
) {
    val context = LocalContext.current.applicationContext
    // Explicit construction (no DI): one coordinator per composition.
    // Remembered so rotation-driven recomposition reuses it; the
    // coordinator itself is stateless across calls except its run guard.
    // (Process death recreates everything; the adopted path then applies.)
    val bootstrap = remember(coordinator) {
        coordinator ?: EnrollmentCoordinator(
            api = HttpE2eeDeviceApi(),
            metadata = FileDeviceMetadataStore(context),
            adapter = AndroidSignalAdapter(),
            vault = AndroidCryptoVault(context, AndroidKeystoreKeyProvider()),
        )
    }
    var enrollState by remember {
        mutableStateOf<EnrollUiState>(
            if (bootstrap.hasAdoptedDevice()) {
                val summary = bootstrap.adoptedSummary()
                EnrollUiState.Done(
                    label = summary?.let { "${it.roleHint} · #${it.signalDeviceId}" }
                        ?: "enrolled",
                    codesAcknowledged = summary?.codesAcknowledged != false,
                )
            } else {
                EnrollUiState.Idle
            }
        )
    }
    val submitting = remember { AtomicBoolean(false) }
    val loggingOut = remember { AtomicBoolean(false) }
    val scope = rememberCoroutineScope()
    // Slice 13 socket, declared early so doLogout (below) can stop it
    // before server revocation even though the messaging graph (which
    // also holds it) is built further down. Rotation-safe via remember.
    val foregroundRealtime = remember(realtimeSocketFactory) {
        if (realtimeSocketFactory != null) {
            RealtimeInbox(socketFactory = realtimeSocketFactory, parentScope = scope)
        } else {
            RealtimeInbox(parentScope = scope)
        }
    }
    // Recovery code: transient Compose state only. Cleared after every
    // attempt and whenever the recovery surface is left; never persisted,
    // never logged, never placed into navigation state.
    var recoveryCode by remember { mutableStateOf("") }
    var approval by remember { mutableStateOf<ApprovalUi?>(null) }
    var approvingId by remember { mutableStateOf<String?>(null) }

    fun mapFinal(final: BootstrapFinal): EnrollUiState = when (final) {
        is BootstrapFinal.Active ->
            EnrollUiState.Done(final.deviceLabel, final.codesAcknowledged)
        is BootstrapFinal.AwaitingCodesAck ->
            EnrollUiState.Codes(final.codes)
        is BootstrapFinal.PendingApproval ->
            EnrollUiState.Pending(final.deviceLabel)
        is BootstrapFinal.Denied ->
            EnrollUiState.Denied(final.deviceLabel)
        is BootstrapFinal.RecoveryRequired ->
            EnrollUiState.Recovery(devices = null, error = null, working = false)
        is BootstrapFinal.ReconciliationRequired ->
            EnrollUiState.Blocked(RECONCILE_MESSAGE)
        is BootstrapFinal.Failed -> when (final.kind) {
            FailKind.TRANSPORT_RETRYABLE ->
                EnrollUiState.Failed(SETUP_FAILED_MESSAGE)
            FailKind.UNAUTHORIZED ->
                EnrollUiState.Failed(UNAUTHORIZED_MESSAGE)
            FailKind.ALREADY_RUNNING ->
                EnrollUiState.Failed(SETUP_FAILED_MESSAGE)
            FailKind.REJECTED, FailKind.IDENTITY_MISMATCH,
            FailKind.MISSING_MATERIAL ->
                EnrollUiState.Blocked(REJECTED_MESSAGE)
        }
    }

    fun recoveryError(kind: FailKind): EnrollUiState = when (kind) {
        FailKind.TRANSPORT_RETRYABLE ->
            EnrollUiState.Recovery(
                devices = (enrollState as? EnrollUiState.Recovery)?.devices,
                error = RECOVERY_TRANSPORT_MESSAGE,
                working = false,
            )
        FailKind.UNAUTHORIZED ->
            EnrollUiState.Failed(UNAUTHORIZED_MESSAGE)
        FailKind.ALREADY_RUNNING ->
            EnrollUiState.Recovery(
                devices = (enrollState as? EnrollUiState.Recovery)?.devices,
                error = SETUP_FAILED_MESSAGE,
                working = false,
            )
        FailKind.REJECTED, FailKind.IDENTITY_MISMATCH,
        FailKind.MISSING_MATERIAL ->
            EnrollUiState.Recovery(
                devices = (enrollState as? EnrollUiState.Recovery)?.devices,
                error = RECOVERY_REJECTED_MESSAGE,
                working = false,
            )
    }

    /**
     * First and only logout affordance. Revokes server-side best-effort,
     * then wipes the persisted session unconditionally — including when
     * offline. Device metadata, vault records, and the wrapping key are
     * never touched here (see SessionRefresher.logout).
     */
    fun doLogout() {
        if (!loggingOut.compareAndSet(false, true)) return
        scope.launch {
            try {
                // Realtime first: the socket must be gone before server
                // revocation tears it down (which would otherwise read as
                // a revocation event on a dying session).
                foregroundRealtime.stop()
                sessionStore?.let { SessionRefresher(authApi, it).logout(serverAddress, session) }
            } finally {
                loggingOut.set(false)
                onLogout()
            }
        }
    }

    fun startBootstrap() {
        if (!submitting.compareAndSet(false, true)) return
        scope.launch {
            try {
                val final = bootstrap.runBootstrap(
                    session, serverAddress,
                    onProgress = { enrollState = EnrollUiState.Working(it) },
                )
                if (final !is BootstrapFinal.RecoveryRequired) {
                    recoveryCode = ""
                }
                enrollState = mapFinal(final)
            } finally {
                submitting.set(false)
            }
        }
    }

    fun setUpAgain() {
        bootstrap.clearDeniedState()
        recoveryCode = ""
        approval = null
        startBootstrap()
    }

    fun submitRecovery(mode: RecoveryMode) {
        if (!submitting.compareAndSet(false, true)) return
        // Snapshot the transient code, then drop it immediately: the
        // coordinator receives it as an argument only.
        val code = recoveryCode
        recoveryCode = ""
        scope.launch {
            try {
                enrollState = EnrollUiState.Recovery(
                    devices = (enrollState as? EnrollUiState.Recovery)?.devices,
                    error = null,
                    working = true,
                )
                val final = bootstrap.recoverWithCode(session, serverAddress, code, mode)
                enrollState = when (final) {
                    is BootstrapFinal.Failed -> recoveryError(final.kind)
                    else -> mapFinal(final)
                }
            } finally {
                submitting.set(false)
            }
        }
    }

    fun loadBindDevices() {
        if (!submitting.compareAndSet(false, true)) return
        scope.launch {
            try {
                enrollState = EnrollUiState.Recovery(
                    devices = (enrollState as? EnrollUiState.Recovery)?.devices,
                    error = null,
                    working = true,
                )
                enrollState = when (val loaded = bootstrap.loadApprovalView(session, serverAddress)) {
                    is ApprovalLoad.Ready ->
                        EnrollUiState.Recovery(
                            devices = loaded.view.active,
                            error = null,
                            working = false,
                        )
                    is ApprovalLoad.Failed -> when (loaded.kind) {
                        FailKind.UNAUTHORIZED ->
                            EnrollUiState.Failed(UNAUTHORIZED_MESSAGE)
                        else ->
                            EnrollUiState.Recovery(
                                devices = null,
                                error = SETUP_FAILED_MESSAGE,
                                working = false,
                            )
                    }
                }
            } finally {
                submitting.set(false)
            }
        }
    }

    fun leaveRecovery() {
        recoveryCode = ""
        enrollState = EnrollUiState.Recovery(devices = null, error = null, working = false)
    }

    fun refreshApproval() {
        scope.launch {
            approval = ApprovalUi.Loading
            approval = when (val loaded = bootstrap.loadApprovalView(session, serverAddress)) {
                is ApprovalLoad.Ready ->
                    ApprovalUi.Ready(loaded.view)
                is ApprovalLoad.Failed -> when (loaded.kind) {
                    FailKind.UNAUTHORIZED -> ApprovalUi.Failed(UNAUTHORIZED_MESSAGE)
                    FailKind.TRANSPORT_RETRYABLE, FailKind.ALREADY_RUNNING ->
                        ApprovalUi.Failed(SETUP_FAILED_MESSAGE)
                    FailKind.REJECTED, FailKind.IDENTITY_MISMATCH,
                    FailKind.MISSING_MATERIAL ->
                        ApprovalUi.Failed(REJECTED_MESSAGE)
                }
            }
        }
    }

    fun approve(deviceId: String) {
        if (approvingId != null) return
        approvingId = deviceId
        scope.launch {
            try {
                when (val outcome = bootstrap.approvePendingDevice(session, serverAddress, deviceId)) {
                    is ApproveOutcome.Approved ->
                        approval = ApprovalUi.Approved(outcome.deviceLabel)
                    ApproveOutcome.StillPending ->
                        refreshApproval()
                    ApproveOutcome.Gone ->
                        refreshApproval()
                    ApproveOutcome.Denied ->
                        approval = ApprovalUi.Failed(APPROVAL_DENIED_MESSAGE)
                    is ApproveOutcome.Failed -> when (outcome.kind) {
                        FailKind.UNAUTHORIZED ->
                            approval = ApprovalUi.Failed(UNAUTHORIZED_MESSAGE)
                        FailKind.TRANSPORT_RETRYABLE, FailKind.ALREADY_RUNNING ->
                            approval = ApprovalUi.Failed(SETUP_FAILED_MESSAGE)
                        FailKind.REJECTED, FailKind.IDENTITY_MISMATCH,
                        FailKind.MISSING_MATERIAL ->
                            approval = ApprovalUi.Failed(REJECTED_MESSAGE)
                    }
                }
            } finally {
                approvingId = null
            }
        }
    }

    fun acknowledge() {
        bootstrap.acknowledgeCodes()
        enrollState = EnrollUiState.Done(
            label = bootstrap.adoptedSummary()?.let { "${it.roleHint} · #${it.signalDeviceId}" }
                ?: "enrolled",
            codesAcknowledged = true,
        )
    }

    // ---- Slice 11 messaging wiring (presentation only; reuse only) ----

    val keys = remember(wrappingKeys) {
        wrappingKeys ?: AndroidKeystoreKeyProvider()
    }
    val messaging = remember(session, serverAddress, keys) {
        val deviceMeta = FileDeviceMetadataStore(context)
        val locks = SessionDeviceLocks()
        val sessionMeta = FileSessionMetadataStore(context)
        val adapter = AndroidSignalAdapter()
        val cryptoVault = AndroidCryptoVault(context, keys)
        val sessionVault =
            AndroidCryptoVault(context, keys, FileSessionMetadataStore.SUBDIR)
        val sealer = MessageContentSealer(keys)
        val api = deviceApi ?: HttpE2eeDeviceApi()
        val db = MessageDatabase.open(context)
        // One shared establisher: its in-flight single-flight map must
        // cover messaging and history sync together.
        val establisher = SessionEstablisher(
            api = api,
            localMetadata = deviceMeta,
            sessions = sessionMeta,
            adapter = adapter,
            identityVault = cryptoVault,
            sessionVault = sessionVault,
        )
        MessagingGraph(
            api = api,
            db = db,
            sessions = sessionMeta,
            sealer = sealer,
            sender = MessageSender(
                api = api,
                localMetadata = deviceMeta,
                sessions = sessionMeta,
                adapter = adapter,
                identityVault = cryptoVault,
                sessionVault = sessionVault,
                deviceLocks = locks,
                db = db,
                contentSealer = sealer,
            ),
            establisher = establisher,
            sweep = ReconciliationSweep(
                api = api,
                localMetadata = deviceMeta,
                sessions = sessionMeta,
                adapter = adapter,
                cryptoVault = cryptoVault,
                sessionVault = sessionVault,
                deviceLocks = locks,
                db = db,
                contentSealer = sealer,
            ),
            historySync = HistorySyncCoordinator(
                api = api,
                localMetadata = deviceMeta,
                sessions = sessionMeta,
                adapter = adapter,
                identityVault = cryptoVault,
                sessionVault = sessionVault,
                establisher = establisher,
                deviceLocks = locks,
                db = db,
                contentSealer = sealer,
                syncMetadata = FileSyncMetadataStore(context),
            ),
            // Separate realtime inbox sharing the graph locks/db/vaults:
            // sweep internals stay untouched; races converge on the same
            // durable rows and the same per-device lock holder.
            rtInbox = InboxProcessor(
                api = api,
                localMetadata = deviceMeta,
                sessions = sessionMeta,
                adapter = adapter,
                cryptoVault = cryptoVault,
                sessionVault = sessionVault,
                deviceLocks = locks,
                db = db,
                contentSealer = sealer,
            ),
            // Same socket instance owned early (see foregroundRealtime):
            // the graph references it but never owns its lifecycle.
            realtime = foregroundRealtime,
        )
    }

    // Foreground scope exit: the realtime socket never outlives the
    // messaging graph it belongs to (rotation-safe: remember survives
    // rotation, so this fires only when Home actually leaves).
    DisposableEffect(messaging) {
        onDispose { messaging.realtime.stop() }
    }

    var selectedConversationId by rememberSaveable { mutableStateOf<String?>(null) }
    var conversations by remember { mutableStateOf<List<ConversationRow>?>(null) }
    var conversationsLoadError by remember { mutableStateOf<String?>(null) }
    var detailPeer by remember { mutableStateOf("") }
    var detailMessages by remember { mutableStateOf<List<MessageRow>?>(null) }
    var detailLoadError by remember { mutableStateOf<String?>(null) }
    var syncing by remember { mutableStateOf(false) }
    var syncError by remember { mutableStateOf<String?>(null) }
    var composerUsername by rememberSaveable { mutableStateOf("") }
    var composerDraft by rememberSaveable { mutableStateOf("") }
    var discoveredDevices by remember { mutableStateOf<List<RecipientDeviceRecord>?>(null) }
    var findingDevices by remember { mutableStateOf(false) }
    var directoryError by remember { mutableStateOf<String?>(null) }
    var selectedDeviceId by remember { mutableStateOf<String?>(null) }
    var sending by remember { mutableStateOf(false) }
    var sendError by remember { mutableStateOf<String?>(null) }
    // ---- Slice 14 friends wiring (session-level; needs no device keys) ----
    val friendsClient = remember(friendsApi) { friendsApi ?: HttpFriendsApi() }
    var friends by remember { mutableStateOf<List<FriendEntry>?>(null) }
    var incomingRequests by remember { mutableStateOf<List<FriendRequestRecord>?>(null) }
    var loadingRoster by remember { mutableStateOf(false) }
    var rosterError by remember { mutableStateOf<String?>(null) }
    var addUsername by rememberSaveable { mutableStateOf("") }
    var sendingFriendRequest by remember { mutableStateOf(false) }
    var addFriendError by remember { mutableStateOf<String?>(null) }
    var addFriendSuccess by remember { mutableStateOf<String?>(null) }
    var respondingRequestId by remember { mutableStateOf<String?>(null) }
    var respondError by remember { mutableStateOf<String?>(null) }

    fun lookupUsername(deviceId: String): String? =
        messaging.sessions.read(deviceId)?.remoteUsername

    fun openRowText(messageId: String, sealed: ByteArray): String? = try {
        messaging.sealer.open(messageId, sealed)
            .toString(Charsets.UTF_8)
            .takeIf { it.isNotEmpty() }
    } catch (_: VaultException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    suspend fun loadConversations() {
        conversationsLoadError = null
        try {
            val grouped = withContext(Dispatchers.IO) {
                messaging.db.messageDao().knownConversationIds()
                    .filter { it.isNotEmpty() }
                    .associateWith { id ->
                        val dao = messaging.db.messageDao()
                        val max = dao.sequencesFor(id).maxOrNull()
                            ?: return@associateWith emptyList()
                        dao.historyPage(
                            id,
                            maxOf(0L, max - PREVIEW_TAIL_LIMIT),
                            PREVIEW_TAIL_LIMIT,
                        )
                    }
            }
            conversations = withContext(Dispatchers.IO) {
                buildConversationList(
                    grouped,
                    { conversationId, rows -> peerLabelFor(conversationId, rows, ::lookupUsername) },
                    { entity ->
                        entity.plaintextSealed?.let { openRowText(entity.messageId, it) }
                            ?: MESSAGE_UNREADABLE
                    },
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            conversationsLoadError = CONVERSATIONS_LOAD_FAILED_MESSAGE
        }
    }

    suspend fun loadDetail(conversationId: String) {
        detailLoadError = null
        try {
            val triple = withContext(Dispatchers.IO) {
                val rows = messaging.db.messageDao()
                    .historyPage(conversationId, 0, MESSAGE_PAGE_LIMIT)
                val peer = peerLabelFor(conversationId, rows, ::lookupUsername)
                val mapped = rows.map { entity ->
                    mapMessageRow(
                        entity,
                        senderLabelFor(entity, ::lookupUsername),
                        ::openRowText,
                    )
                }
                Triple(peer, mapped, Unit)
            }
            detailPeer = triple.first
            detailMessages = triple.second
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            detailLoadError = MESSAGES_LOAD_FAILED_MESSAGE
        }
    }

    fun openConversation(conversationId: String) {
        selectedConversationId = conversationId
        detailMessages = null
        detailLoadError = null
        sendError = null
        // Prefill the composer only with a resolved username, never with
        // a fallback conversation ID.
        val peer = conversations
            ?.firstOrNull { it.conversationId == conversationId }
            ?.peerLabel
        if (composerUsername.isBlank() && peer != null && peer != conversationId) {
            composerUsername = peer
        }
        discoveredDevices = null
        selectedDeviceId = null
        directoryError = null
        scope.launch { loadDetail(conversationId) }
    }

    fun closeConversation() {
        selectedConversationId = null
        detailMessages = null
        detailLoadError = null
    }

    /**
     * Slice 13 foreground realtime: idempotent ensure-started called only
     * after a clean sweep. The subscribed device is the adopted bound
     * device id (never user-selected); the server enforces the exact
     * subscription match regardless. Unenrolled/handle-less installs
     * never subscribe.
     */
    fun ensureRealtime() {
        val deviceId = bootstrap.adoptedSummary()?.deviceId
        if (deviceId.isNullOrBlank()) return
        val callbacks = object : RealtimeInbox.Callbacks {
            override suspend fun onItem(item: com.samvaad.android.enroll.MailboxItem) {
                try {
                    messaging.rtInbox.receiveOne(session, serverAddress, item)
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    // Ingest failure stays local: the mailbox row remains
                    // and the next sweep recovers it.
                }
                loadConversations()
                selectedConversationId?.let { loadDetail(it) }
            }

            override suspend fun refreshSession(): AuthSession? {
                val store = sessionStore ?: return null
                return when (
                    val restored = SessionRefresher(authApi, store).restoreSession()
                ) {
                    is SessionRefresher.RestoreOutcome.Authenticated -> restored.session
                    else -> null
                }
            }

            override fun onStopped(reason: RealtimeInbox.StopReason) {
                scope.launch {
                    when (reason) {
                        // Session is dead: converge to login via the
                        // existing logout routing (no server call needed).
                        RealtimeInbox.StopReason.AuthExhausted -> onLogout()
                        // Device state changed: re-query authoritative
                        // state so denied/revoked UX stays authoritative.
                        RealtimeInbox.StopReason.Revoked -> refreshApproval()
                        // Transport budget spent: manual Sync remains and
                        // re-ensures realtime on its next clean run.
                        RealtimeInbox.StopReason.AttemptsExhausted -> Unit
                    }
                }
            }
        }
        try {
            messaging.realtime.start(session, serverAddress, deviceId, callbacks)
        } catch (_: IllegalArgumentException) {
            // Invalid address/device programming error guard: realtime
            // stays down; manual Sync remains fully functional.
        }
    }

    /**
     * Sessions already proven bound to the adopted device in this
     * process. The server short-circuits the already-bound check without
     * cryptography, but skipping it entirely keeps steady-state
     * Sync/Send at zero extra calls. Keyed by session id: a fresh login
     * always re-proves.
     */
    val boundSessions = remember { mutableSetOf<String>() }

    /**
     * Proactive session→device recovery for device-scoped calls. At most
     * one handshake per session through this path (plus one per explicit
     * user retry): callers never loop on refusal — every non-transport
     * outcome converges to a surfaced message. [syncFailed] selects which
     * error slot the message lands in.
     */
    suspend fun ensureSessionBound(syncFailed: Boolean): Boolean {
        fun fail(message: String): Boolean {
            if (syncFailed) syncError = message else sendError = message
            return false
        }
        if (!bootstrap.hasAdoptedDevice()) return true
        if (boundSessions.contains(session.sessionId)) return true
        return when (val outcome = bootstrap.ensureSessionBound(session, serverAddress)) {
            is SessionBindOutcome.Bound -> {
                boundSessions.add(session.sessionId)
                true
            }
            is SessionBindOutcome.NoAdoptedDevice -> true
            is SessionBindOutcome.TransportRetryable ->
                fail(BIND_FAILED_MESSAGE)
            is SessionBindOutcome.NeedsLogin -> {
                onLogout()
                false
            }
            is SessionBindOutcome.CryptoUnavailable,
            is SessionBindOutcome.DeviceUnavailable ->
                fail(BIND_DEVICE_MESSAGE)
        }
    }

    fun sync() {
        // Main-thread guard like the approval taps: at most one sweep runs.
        if (syncing) return
        syncing = true
        scope.launch {
            try {
                // Session/device binding is a precondition for every
                // device-scoped call below: one bounded recovery attempt,
                // then converge or surface — never a retry loop.
                if (!ensureSessionBound(syncFailed = true)) return@launch
                val report = messaging.sweep.sweep(session, serverAddress)
                syncError = sweepErrorMessage(report)
                // History sync runs after the sweep on every manual Sync:
                // same guard, same bounded headless shape. Sweep errors
                // take precedence (existing behavior preserved); a history
                // error surfaces only when the sweep itself is clean.
                // Non-PRIMARY/non-COMPANION devices report nothing here
                // (the coordinator returns a clean empty report).
                if (syncError == null) {
                    val history = messaging.historySync.sync(session, serverAddress, identifier)
                    syncError = history.error
                }
                if (syncError == null) {
                    // Sweep-before-subscribe: realtime starts only on a
                    // clean sweep so the live stream only adds new items.
                    ensureRealtime()
                }
                loadConversations()
                selectedConversationId?.let { loadDetail(it) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                syncError = SYNC_FAILED_MESSAGE
            } finally {
                syncing = false
            }
        }
    }

    fun findDevices() {
        val username = composerUsername.trim()
        if (username.isEmpty() || findingDevices) return
        findingDevices = true
        scope.launch {
            try {
                discoveredDevices =
                    messaging.api.listRecipientDevices(session, serverAddress, username)
                directoryError = null
                selectedDeviceId = null
            } catch (e: EnrollException.Forbidden) {
                directoryError = NOT_FRIENDS_MESSAGE
            } catch (e: EnrollException.NotFound) {
                directoryError = USER_NOT_FOUND_MESSAGE
            } catch (e: EnrollException.Unauthorized) {
                directoryError = UNAUTHORIZED_MESSAGE
            } catch (e: CancellationException) {
                throw e
            } catch (_: EnrollException) {
                directoryError = DIRECTORY_FAILED_MESSAGE
            } catch (_: IOException) {
                directoryError = DIRECTORY_FAILED_MESSAGE
            } finally {
                findingDevices = false
            }
        }
    }

    fun send() {
        // Main-thread single-flight: each tap is at most one logical send,
        // so duplicate taps can never mint duplicate messages.
        if (sending) return
        val deviceId = selectedDeviceId ?: return
        val username = composerUsername.trim()
        val text = composerDraft
        if (username.isEmpty() || text.isBlank()) return
        sending = true
        scope.launch {
            try {
                // Same precondition as sync(): a send without a bound
                // session is a guaranteed 403, so recover first, once.
                if (!ensureSessionBound(syncFailed = false)) return@launch
                when (val established = messaging.establisher.establish(
                    session, serverAddress, username, deviceId
                )) {
                    is SessionEstablishResult.Established -> {
                        when (val sent = messaging.sender.send(
                            session, serverAddress, username, deviceId,
                            text.toByteArray(Charsets.UTF_8),
                        )) {
                            is SendResult.Sent -> {
                                composerDraft = ""
                                sendError = null
                                selectedConversationId = sent.conversationId
                                loadConversations()
                                loadDetail(sent.conversationId)
                            }
                            is SendResult.Failed -> {
                                // The durable row (if any) is reloaded below;
                                // the live retry handle is intentionally not
                                // kept: Sync recovers durable rows instead.
                                sendError = sendFailureMessage(sent.kind)
                                loadConversations()
                                selectedConversationId?.let { loadDetail(it) }
                            }
                        }
                    }
                    else -> sendError =
                        establishFailureMessage(established) ?: SEND_FAILED_MESSAGE
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                sendError = SEND_FAILED_MESSAGE
            } finally {
                sending = false
            }
        }
    }

    // ---- Slice 14 friends actions (presentation only; reuse only) ----

    fun refreshRoster() {
        // Main-thread single-flight like the approval taps.
        if (loadingRoster) return
        loadingRoster = true
        scope.launch {
            try {
                friends = friendsClient.listFriends(session, serverAddress)
                incomingRequests = friendsClient.listIncoming(session, serverAddress)
                rosterError = null
            } catch (e: FriendException.Unauthorized) {
                rosterError = UNAUTHORIZED_MESSAGE
            } catch (e: CancellationException) {
                throw e
            } catch (_: IOException) {
                rosterError = FRIENDS_FAILED_MESSAGE
            } finally {
                loadingRoster = false
            }
        }
    }

    fun sendFriendRequest() {
        val username = addUsername.trim()
        if (username.isEmpty() || sendingFriendRequest) return
        sendingFriendRequest = true
        scope.launch {
            try {
                friendsClient.sendRequest(session, serverAddress, username)
                addUsername = ""
                addFriendError = null
                addFriendSuccess = "Request sent to $username."
                refreshRoster()
            } catch (e: FriendException.NotFound) {
                addFriendError = USER_NOT_FOUND_MESSAGE
                addFriendSuccess = null
            } catch (e: FriendException.Forbidden) {
                addFriendError = ADD_SELF_MESSAGE
                addFriendSuccess = null
            } catch (e: FriendException.Conflict) {
                addFriendError = ALREADY_FRIENDS_MESSAGE
                addFriendSuccess = null
            } catch (e: FriendException.Unauthorized) {
                addFriendError = UNAUTHORIZED_MESSAGE
                addFriendSuccess = null
            } catch (e: CancellationException) {
                throw e
            } catch (_: IOException) {
                addFriendError = FRIENDS_FAILED_MESSAGE
                addFriendSuccess = null
            } finally {
                sendingFriendRequest = false
            }
        }
    }

    fun respondToRequest(requestId: String, accept: Boolean) {
        // Main-thread single-flight: one accept/reject at a time so a
        // double tap can never transition the same request twice.
        if (respondingRequestId != null) return
        respondingRequestId = requestId
        scope.launch {
            try {
                if (accept) {
                    friendsClient.acceptRequest(session, serverAddress, requestId)
                } else {
                    friendsClient.rejectRequest(session, serverAddress, requestId)
                }
                respondError = null
                refreshRoster()
            } catch (e: FriendException.Unauthorized) {
                respondError = UNAUTHORIZED_MESSAGE
            } catch (e: FriendException.NotFound) {
                respondError = REQUEST_GONE_MESSAGE
            } catch (e: FriendException.Conflict) {
                respondError = REQUEST_GONE_MESSAGE
            } catch (e: CancellationException) {
                throw e
            } catch (_: IOException) {
                respondError = FRIENDS_FAILED_MESSAGE
            } finally {
                respondingRequestId = null
            }
        }
    }

    val codes = (enrollState as? EnrollUiState.Codes)?.codes
    if (codes != null) {
        RecoveryCodesScreen(codes = codes, onAcknowledge = ::acknowledge)
        return
    }

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Image(
                painter = painterResource(R.drawable.samvaad_logo),
                contentDescription = "Samvaad logo",
                modifier = Modifier.size(96.dp)
            )
            Text(
                text = "Samvaad",
                style = MaterialTheme.typography.headlineMedium
            )
            Text(text = "Signed in as $identifier")
            when (val state = enrollState) {
                is EnrollUiState.Idle -> {
                    Text(
                        text = "This device is not set up for encrypted messaging yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Button(onClick = ::startBootstrap) {
                        Text("Set up this device")
                    }
                }
                is EnrollUiState.Working -> {
                    CircularProgressIndicator(modifier = Modifier.size(32.dp))
                    Text(
                        text = when (state.progress) {
                            BootstrapProgress.Preparing -> "Preparing device…"
                            BootstrapProgress.Enrolling -> "Registering device…"
                            BootstrapProgress.UploadingPrekeys -> "Uploading keys…"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                is EnrollUiState.Done -> {
                    // Bind-recovered installs hold no local private material
                    // (bind accepts none): report the bound state honestly
                    // instead of claiming full messaging readiness. Missing
                    // metadata defaults to the normal message; only a
                    // present-but-handle-less record qualifies it.
                    val hasLocalKeys = bootstrap.adoptedSummary()?.hasLocalKeys != false
                    if (hasLocalKeys) {
                        Text(text = "Device ready (${state.label})")
                    } else {
                        Text(text = "Device bound (${state.label})")
                        Text(
                            text = "This installation is bound to the existing " +
                                "server device, but its private messaging keys " +
                                "are not present here, so messaging remains " +
                                "unavailable on this installation. To enable " +
                                "messaging here, recover as a new device.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (!state.codesAcknowledged) {
                        Text(
                            text = "Recovery codes were not confirmed. " +
                                "A future update will let you rotate them.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    when (val approvalState = approval) {
                        null -> {
                            Button(onClick = ::refreshApproval) {
                                Text("Review pending devices")
                            }
                        }
                        ApprovalUi.Loading -> {
                            CircularProgressIndicator(modifier = Modifier.size(32.dp))
                        }
                        is ApprovalUi.Ready -> {
                            val view = approvalState.view
                            if (!view.selfActive) {
                                Text(
                                    text = APPROVAL_INACTIVE_MESSAGE,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            } else if (view.pending.isEmpty()) {
                                Text(
                                    text = APPROVAL_NONE_MESSAGE,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            } else {
                                view.pending.forEach { device ->
                                    Text(
                                        text = "Pending device (${device.deviceRole} · #${device.signalDeviceId})",
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                    val busy = approvingId != null
                                    Button(
                                        onClick = { approve(device.deviceId) },
                                        enabled = !busy,
                                    ) {
                                        Text(
                                            if (approvingId == device.deviceId) {
                                                "Approving…"
                                            } else {
                                                "Approve"
                                            }
                                        )
                                    }
                                }
                            }
                            TextButton(onClick = ::refreshApproval) {
                                Text("Refresh")
                            }
                        }
                        is ApprovalUi.Failed -> {
                            Text(
                                text = approvalState.message,
                                color = MaterialTheme.colorScheme.error
                            )
                            TextButton(onClick = ::refreshApproval) {
                                Text("Retry")
                            }
                        }
                        is ApprovalUi.Approved -> {
                            Text(
                                text = "Device approved (${approvalState.label})",
                                style = MaterialTheme.typography.bodyMedium
                            )
                            TextButton(onClick = ::refreshApproval) {
                                Text("Refresh")
                            }
                        }
                    }
                    // Slice 14 friends: session-level only (no device keys
                    // needed), so visible in Done even on handle-less
                    // installs. Accepting here unblocks the composer below.
                    LaunchedEffect(Unit) {
                        refreshRoster()
                    }
                    FriendsSection(
                        friends = friends,
                        incoming = incomingRequests,
                        loadingRoster = loadingRoster,
                        rosterError = rosterError,
                        onRefreshRoster = ::refreshRoster,
                        addUsername = addUsername,
                        onAddUsernameChange = {
                            addUsername = it
                            addFriendError = null
                            addFriendSuccess = null
                        },
                        sendingRequest = sendingFriendRequest,
                        addFriendError = addFriendError,
                        addFriendSuccess = addFriendSuccess,
                        onSendRequest = ::sendFriendRequest,
                        respondingRequestId = respondingRequestId,
                        respondError = respondError,
                        onAccept = { respondToRequest(it, accept = true) },
                        onReject = { respondToRequest(it, accept = false) },
                    )
                    // Slice 11 messaging is available only with local
                    // crypto handles. Handle-less ("Device bound") installs
                    // stay fail-closed: no list, no composer, no sync.
                    if (hasLocalKeys) {
                        LaunchedEffect(Unit) {
                            loadConversations()
                        }

                        @Composable
                        fun MessageComposer() {
                            ComposerUi(
                                username = composerUsername,
                                onUsernameChange = {
                                    composerUsername = it
                                    discoveredDevices = null
                                    selectedDeviceId = null
                                    directoryError = null
                                },
                                draft = composerDraft,
                                onDraftChange = { composerDraft = it },
                                devices = discoveredDevices,
                                findingDevices = findingDevices,
                                directoryError = directoryError,
                                selectedDeviceId = selectedDeviceId,
                                onFindDevices = ::findDevices,
                                onSelectDevice = { selectedDeviceId = it },
                                sending = sending,
                                sendError = sendError,
                                onSend = ::send,
                            )
                        }

                        val openId = selectedConversationId
                        if (openId == null) {
                            ConversationListUi(
                                conversations = conversations,
                                loadError = conversationsLoadError,
                                onRetryLoad = {
                                    scope.launch { loadConversations() }
                                },
                                syncing = syncing,
                                syncError = syncError,
                                onSync = ::sync,
                                onSelect = ::openConversation,
                            )
                            MessageComposer()
                        } else {
                            BackHandler {
                                closeConversation()
                            }
                            ConversationDetailUi(
                                peerLabel = detailPeer.ifEmpty { openId },
                                messages = detailMessages,
                                loadError = detailLoadError,
                                onRetryLoad = {
                                    scope.launch { loadDetail(openId) }
                                },
                                syncing = syncing,
                                syncError = syncError,
                                onBack = ::closeConversation,
                                onSync = ::sync,
                                composer = { MessageComposer() },
                            )
                        }
                    }
                }
                is EnrollUiState.Failed -> {
                    Text(
                        text = state.message,
                        color = MaterialTheme.colorScheme.error
                    )
                    Button(onClick = ::startBootstrap) {
                        Text("Retry setup")
                    }
                }
                is EnrollUiState.Blocked -> {
                    Text(
                        text = state.message,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                is EnrollUiState.Pending -> {
                    Text(
                        text = PENDING_MESSAGE,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "Waiting as ${state.label}.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Button(onClick = ::startBootstrap) {
                        Text("Check status")
                    }
                }
                is EnrollUiState.Denied -> {
                    Text(
                        text = DENIED_MESSAGE,
                        color = MaterialTheme.colorScheme.error
                    )
                    Text(
                        text = "Was waiting as ${state.label}.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Button(onClick = ::setUpAgain) {
                        Text("Set up this device again")
                    }
                }
                is EnrollUiState.Recovery -> {
                    Text(
                        text = RECOVERY_MESSAGE,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = RECOVERY_HINT,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = recoveryCode,
                        onValueChange = { recoveryCode = it },
                        label = { Text(RECOVERY_CODE_LABEL) },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        enabled = !state.working,
                    )
                    if (state.working) {
                        CircularProgressIndicator(modifier = Modifier.size(32.dp))
                    }
                    Button(
                        onClick = { submitRecovery(RecoveryMode.NewDevice) },
                        enabled = recoveryCode.isNotBlank() && !state.working,
                    ) {
                        Text("Recover as new device")
                    }
                    val devices = state.devices
                    if (devices == null) {
                        TextButton(
                            onClick = ::loadBindDevices,
                            enabled = !state.working,
                        ) {
                            Text("Bind an existing device instead")
                        }
                    } else if (devices.isEmpty()) {
                        Text(
                            text = "No active devices to bind to on this account.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        Text(
                            text = "Choose an active device to bind to:",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        devices.forEach { device ->
                            Button(
                                onClick = {
                                    submitRecovery(RecoveryMode.Bind(device.deviceId))
                                },
                                enabled = recoveryCode.isNotBlank() && !state.working,
                            ) {
                                Text("Bind ${device.deviceRole} · #${device.signalDeviceId}")
                            }
                        }
                    }
                    state.error?.let { error ->
                        Text(
                            text = error,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    TextButton(
                        onClick = ::leaveRecovery,
                        enabled = !state.working,
                    ) {
                        Text("Back")
                    }
                }
                is EnrollUiState.Codes -> Unit // handled above
            }
            TextButton(onClick = ::doLogout) {
                Text("Log out")
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun HomeScreenPreview() {
    SamvaadTheme {
        Text("HomeScreen preview requires a live session; see EntryScreen.")
    }
}
