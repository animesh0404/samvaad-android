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
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.enroll.BootstrapFinal
import com.samvaad.android.enroll.BootstrapProgress
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.enroll.FailKind
import com.samvaad.android.enroll.FileDeviceMetadataStore
import com.samvaad.android.enroll.HttpE2eeDeviceApi
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
                when (val final = bootstrap.runBootstrap(
                    session, serverAddress,
                    onProgress = { enrollState = EnrollUiState.Working(it) },
                )) {
                    is BootstrapFinal.Active -> enrollState =
                        EnrollUiState.Done(final.deviceLabel, final.codesAcknowledged)
                    is BootstrapFinal.AwaitingCodesAck -> enrollState =
                        EnrollUiState.Codes(final.codes)
                    is BootstrapFinal.PendingApproval -> enrollState =
                        EnrollUiState.Blocked(PENDING_MESSAGE)
                    is BootstrapFinal.RecoveryRequired -> enrollState =
                        EnrollUiState.Blocked(RECOVERY_MESSAGE)
                    is BootstrapFinal.ReconciliationRequired -> enrollState =
                        EnrollUiState.Blocked(RECONCILE_MESSAGE)
                    is BootstrapFinal.Failed -> enrollState = when (final.kind) {
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
            } finally {
                submitting.set(false)
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
                    Text(text = "Device ready (${state.label})")
                    if (!state.codesAcknowledged) {
                        Text(
                            text = "Recovery codes were not confirmed. " +
                                "A future update will let you rotate them.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
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
