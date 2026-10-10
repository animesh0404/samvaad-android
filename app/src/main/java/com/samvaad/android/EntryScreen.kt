package com.samvaad.android

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.samvaad.android.session.SessionRefresher
import com.samvaad.android.session.SessionStore
import com.samvaad.android.ui.ds.SamvaadTextField
import com.samvaad.android.ui.ds.StatusCard
import com.samvaad.android.ui.ds.StatusKind
import com.samvaad.android.ui.shell.SamvaadAppShell
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadSpacing
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.IOException
import java.net.MalformedURLException
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * Samvaad entry/authentication screen (Slices 1–2).
 *
 * Form state lives in Compose [remember] state. Continue performs a real
 * `POST /api/auth/login` through [AuthApi] and keeps the resulting
 * [AuthSession] ONLY in memory. No persistence, refresh scheduler,
 * navigation, or E2EE.
 */
sealed interface LoginUiState {
    data object Idle : LoginUiState
    data object Loading : LoginUiState
    data class Authenticated(val session: AuthSession, val serverAddress: String) : LoginUiState
    /** [message] is always one of the fixed safe strings below. */
    data class Failed(val message: String) : LoginUiState
}

private const val BLANK_FORM_MESSAGE =
    "Enter a server address, username, and password."
private const val BAD_ADDRESS_MESSAGE =
    "Enter a valid server address, e.g. https://host:8080."
private const val REJECTED_MESSAGE =
    "Sign in failed. Check your details and try again."
private const val UNREACHABLE_MESSAGE =
    "Cannot reach the server. Check the address and try again."

/**
 * Explicit HTTPS URL; plain HTTP is rejected locally. No silent scheme
 * substitution and no cleartext. Null when invalid or insecure.
 */
private fun normalizeServerAddress(raw: String): String? {
    return try {
        val url = URL(raw)
        if (url.protocol != "https") return null
        if (url.host.isNullOrBlank()) return null
        raw.trimEnd('/')
    } catch (e: MalformedURLException) {
        null
    }
}

@Composable
fun SamvaadEntryScreen(
    authApi: AuthApi = HttpAuthApi(),
    /**
     * Optional durability for the fresh login. When present, the refresh
     * bundle is persisted before the authenticated state is treated as
     * restart-recoverable. A persistence failure still enters Home with
     * the live session (pre-slice behavior) and claims nothing durable.
     */
    sessionStore: SessionStore? = null,
    /** One-shot notice (e.g. expired session) shown on the form. */
    noticeMessage: String? = null,
) {
    var serverAddress by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var loginState by remember(noticeMessage) {
        mutableStateOf<LoginUiState>(
            noticeMessage?.let(LoginUiState::Failed) ?: LoginUiState.Idle
        )
    }
    val submitting = remember { AtomicBoolean(false) }
    val scope = rememberCoroutineScope()

    val loading = loginState == LoginUiState.Loading

    fun startLogin() {
        if (!submitting.compareAndSet(false, true)) return
        val identifier = username.trim()
        if (serverAddress.isBlank() || identifier.isBlank() || password.isEmpty()) {
            loginState = LoginUiState.Failed(BLANK_FORM_MESSAGE)
            submitting.set(false)
            return
        }
        val normalized = normalizeServerAddress(serverAddress.trim())
        if (normalized == null) {
            loginState = LoginUiState.Failed(BAD_ADDRESS_MESSAGE)
            submitting.set(false)
            return
        }
        loginState = LoginUiState.Loading
        scope.launch {
            try {
                val session = authApi.login(
                    LoginRequest(
                        serverAddress = normalized,
                        identifier = identifier,
                        password = password,
                    )
                )
                password = ""
                if (sessionStore != null) {
                    try {
                        SessionRefresher(authApi, sessionStore)
                            .persistLogin(normalized, session)
                    } catch (_: Exception) {
                        // Durability unavailable: proceed with the live
                        // session anyway. Restart recovery simply won't
                        // exist for this login; nothing durable is claimed.
                    }
                }
                loginState = LoginUiState.Authenticated(session, normalized)
            } catch (e: CancellationException) {
                submitting.set(false)
                throw e
            } catch (e: AuthRejectedException) {
                loginState = LoginUiState.Failed(REJECTED_MESSAGE)
            } catch (e: IOException) {
                loginState = LoginUiState.Failed(UNREACHABLE_MESSAGE)
            } catch (e: Exception) {
                loginState = LoginUiState.Failed(REJECTED_MESSAGE)
            } finally {
                submitting.set(false)
            }
        }
    }

    val authenticated = loginState as? LoginUiState.Authenticated
    if (authenticated != null) {
        SamvaadAppShell(
            identifier = authenticated.session.identifier,
            session = authenticated.session,
            serverAddress = authenticated.serverAddress,
            authApi = authApi,
            sessionStore = sessionStore,
            onLogout = { loginState = LoginUiState.Idle },
        )
        return
    }

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .consumeWindowInsets(innerPadding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(
                    horizontal = SamvaadSpacing.XLarge,
                    vertical = SamvaadSpacing.XLarge,
                ),
            verticalArrangement = Arrangement.spacedBy(
                SamvaadSpacing.Large,
                Alignment.CenterVertically,
            ),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Column(
                modifier = Modifier
                    // Slice H: widthIn FIRST — fillMaxWidth fixes
                    // minWidth to the window, which would coerce the
                    // cap back up and silently uncap wide windows.
                    .widthIn(max = SamvaadDimens.MaxContentWidth)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.Large),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Image(
                    painter = painterResource(R.drawable.samvaad_logo),
                    contentDescription = "Samvaad logo",
                    modifier = Modifier.size(SamvaadDimens.BrandMarkSize)
                )
                Text(
                    text = "Samvaad",
                    style = MaterialTheme.typography.headlineLarge
                )
                Text(
                    text = "Private messaging for you and your friends. " +
                        "Sign in with your Samvaad server account.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                SamvaadTextField(
                    value = serverAddress,
                    onValueChange = { serverAddress = it },
                    label = "Server address",
                    enabled = !loading,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                    supportingText = "Your Samvaad server address, starting with https://",
                )
                SamvaadTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = "Username",
                    enabled = !loading,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                )
                SamvaadTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = "Password",
                    enabled = !loading,
                    visualTransformation = if (passwordVisible) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    trailingContent = {
                        TextButton(
                            onClick = { passwordVisible = !passwordVisible },
                            enabled = !loading,
                            // Slice H: meets the 48dp touch target; the
                            // field itself is taller, so no growth.
                            modifier = Modifier.heightIn(
                                min = SamvaadDimens.MinTouchTarget,
                            ),
                        ) {
                            Text(if (passwordVisible) "Hide" else "Show")
                        }
                    },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done
                    ),
                    keyboardActions = KeyboardActions(
                        onDone = { startLogin() }
                    ),
                )
                Button(
                    onClick = ::startLogin,
                    enabled = !loading,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = SamvaadDimens.ActionMinHeight),
                ) {
                    if (loading) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(SamvaadSpacing.Small),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                strokeWidth = 2.dp
                            )
                            Text("Continue")
                        }
                    } else {
                        Text("Continue")
                    }
                }
                val failed = loginState as? LoginUiState.Failed
                if (failed != null) {
                    StatusCard(
                        kind = StatusKind.Error,
                        message = failed.message,
                    )
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun SamvaadEntryScreenPreview() {
    SamvaadTheme {
        SamvaadEntryScreen()
    }
}
