package com.samvaad.android

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.samvaad.android.crypto.AndroidKeystoreKeyProvider
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.session.SessionRefresher
import com.samvaad.android.session.SessionStore
import com.samvaad.android.ui.shell.SamvaadAppShell
import com.samvaad.android.ui.theme.SamvaadTheme

/**
 * Root authentication gate (no navigation framework).
 *
 * Launch: silent refresh of the persisted bundle → [HomeScreen]; absent
 * or unusable bundle → [SamvaadEntryScreen] (with the expired-session
 * message when a record existed but could not yield a session). Logout
 * returns here to a clean login form.
 *
 * Tokens never enter rendered text; all messages are fixed safe strings.
 */
private sealed interface GateState {
    data object Restoring : GateState
    data class Home(val session: AuthSession, val serverAddress: String) : GateState
    data class Login(val noticeMessage: String?) : GateState
}

private const val SESSION_EXPIRED_MESSAGE =
    "Your session has expired. Please sign in again."
private const val RESTORE_UNREACHABLE_MESSAGE =
    "Cannot reach the server. Check the connection and try again."
private const val RESTORING_MESSAGE = "Restoring session…"

@Composable
fun SessionGate(
    authApi: AuthApi = HttpAuthApi(),
    // Test seams: production passes null and gets real implementations.
    sessionStore: SessionStore? = null,
    refresher: SessionRefresher? = null,
) {
    val context = LocalContext.current.applicationContext
    val store = remember(sessionStore) {
        sessionStore ?: FileSessionStore(context, AndroidKeystoreKeyProvider())
    }
    val restore = remember(refresher) {
        refresher ?: SessionRefresher(authApi, store)
    }
    var gate by remember { mutableStateOf<GateState>(GateState.Restoring) }

    LaunchedEffect(Unit) {
        gate = when (val outcome = restore.restoreSession()) {
            is SessionRefresher.RestoreOutcome.Authenticated ->
                GateState.Home(outcome.session, outcome.serverAddress)
            is SessionRefresher.RestoreOutcome.NoStoredSession ->
                GateState.Login(null)
            is SessionRefresher.RestoreOutcome.SessionExpired ->
                GateState.Login(SESSION_EXPIRED_MESSAGE)
            is SessionRefresher.RestoreOutcome.Unreachable ->
                GateState.Login(RESTORE_UNREACHABLE_MESSAGE)
        }
    }

    SamvaadTheme {
        when (val state = gate) {
            is GateState.Restoring -> Scaffold(modifier = Modifier.fillMaxSize()) { inner ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(inner)
                        .padding(24.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(32.dp))
                    Text(
                        text = RESTORING_MESSAGE,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            is GateState.Home -> SamvaadAppShell(
                identifier = state.session.identifier,
                session = state.session,
                serverAddress = state.serverAddress,
                authApi = authApi,
                sessionStore = store,
                onLogout = { gate = GateState.Login(null) },
            )
            is GateState.Login -> SamvaadEntryScreen(
                authApi = authApi,
                sessionStore = store,
                noticeMessage = state.noticeMessage,
            )
        }
    }
}
