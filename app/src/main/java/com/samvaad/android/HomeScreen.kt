package com.samvaad.android

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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
import com.samvaad.android.enroll.ApprovalLoad
import com.samvaad.android.enroll.ApprovalView
import com.samvaad.android.enroll.ApproveOutcome
import com.samvaad.android.enroll.BootstrapFinal
import com.samvaad.android.enroll.BootstrapProgress
import com.samvaad.android.enroll.DeviceRecord
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FailKind
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.HttpE2eeDeviceApi
import com.samvaad.android.enroll.RecoveryMode
import com.samvaad.android.session.SessionRefresher
import com.samvaad.android.session.SessionStore
import com.samvaad.android.ui.theme.SamvaadTheme
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.launch

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
    onLogout: () -> Unit = {},
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
