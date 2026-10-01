package com.samvaad.android

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
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
    data class Authenticated(val session: AuthSession) : LoginUiState
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

/** Explicit http/https URL; no silent scheme substitution. Null when invalid. */
private fun normalizeServerAddress(raw: String): String? {
    return try {
        val url = URL(raw)
        if (url.protocol != "http" && url.protocol != "https") return null
        if (url.host.isNullOrBlank()) return null
        raw.trimEnd('/')
    } catch (e: MalformedURLException) {
        null
    }
}

@Composable
fun SamvaadEntryScreen(authApi: AuthApi = HttpAuthApi()) {
    var serverAddress by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var loginState by remember { mutableStateOf<LoginUiState>(LoginUiState.Idle) }
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
                loginState = LoginUiState.Authenticated(session)
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
                modifier = Modifier.size(120.dp)
            )
            Text(
                text = "Samvaad",
                style = MaterialTheme.typography.headlineMedium
            )
            val authenticated = loginState as? LoginUiState.Authenticated
            if (authenticated != null) {
                Text(text = "Signed in as ${authenticated.session.identifier}")
            } else {
                OutlinedTextField(
                    value = serverAddress,
                    onValueChange = { serverAddress = it },
                    label = { Text("Server address") },
                    singleLine = true,
                    enabled = !loading,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("Username") },
                    singleLine = true,
                    enabled = !loading,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    singleLine = true,
                    enabled = !loading,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done
                    ),
                    modifier = Modifier.fillMaxWidth()
                )
                Button(
                    onClick = ::startLogin,
                    enabled = !loading,
                ) {
                    if (loading) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
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
                    Text(
                        text = failed.message,
                        color = MaterialTheme.colorScheme.error
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
