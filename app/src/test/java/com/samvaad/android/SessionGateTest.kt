package com.samvaad.android

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ApplicationProvider
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.session.FileSessionStore
import com.samvaad.android.session.PersistedSession
import com.samvaad.android.session.SessionRefresher
import com.samvaad.android.session.SessionStore
import com.samvaad.android.session.SessionStoreException
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Session gate + login-persistence UI tests. Real store (ephemeral AES
 * key) and real refresher; only HTTP is faked. No live server.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SessionGateTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = key
    }

    private class FakeAuthApi : AuthApi {
        var loginResult: Result<AuthSession> = Result.failure(AuthRejectedException())
        var refreshHandler: suspend (String, String) -> RefreshedSession =
            { _, _ -> throw AssertionError("unexpected refresh") }
        var logoutHandler: (String, String) -> Unit = { _, _ -> }

        override suspend fun login(request: LoginRequest): AuthSession =
            loginResult.getOrThrow()

        override suspend fun refresh(serverAddress: String, refreshToken: String): RefreshedSession =
            refreshHandler(serverAddress, refreshToken)

        override suspend fun logout(serverAddress: String, accessToken: String) =
            logoutHandler(serverAddress, accessToken)
    }

    private class ThrowingStore(private val delegate: SessionStore) : SessionStore {
        override fun save(record: PersistedSession): Nothing =
            throw SessionStoreException("disk full")

        override fun load(): PersistedSession? = delegate.load()
        override fun clear() = delegate.clear()
    }

    private lateinit var context: Context
    private lateinit var fake: FakeAuthApi
    private lateinit var store: FileSessionStore

    private fun refresher() = SessionRefresher(fake, store)

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        File(context.noBackupFilesDir, FileSessionStore.SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, AndroidCryptoVault.STORE_SUBDIR).deleteRecursively()
        File(context.noBackupFilesDir, "device-metadata").deleteRecursively()
        fake = FakeAuthApi()
        store = FileSessionStore(context, EphemeralKeys())
    }

    private fun seedValid() {
        store.save(
            PersistedSession(
                serverAddress = "https://example.test:8080",
                identifier = "alice",
                refreshToken = "refresh-1",
                sessionId = "11111111-2222-3333-4444-555555555555",
                refreshExpiresAtEpochMillis = System.currentTimeMillis() + 86_400_000,
            )
        )
    }

    @Test
    fun restore_success_showsHome() {
        seedValid()
        fake.refreshHandler = { _, _ ->
            RefreshedSession("access-2", "refresh-2", "11111111-2222-3333-4444-555555555555")
        }
        composeTestRule.setContent {
            SamvaadTheme {
                SessionGate(
                    authApi = fake,
                    sessionStore = store,
                    refresher = SessionRefresher(fake, store),
                )
            }
        }
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Signed in as alice").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        composeTestRule.onNodeWithText("Signed in as alice").assertIsDisplayed()
    }

    @Test
    fun restore_rejected_showsLoginWithExpiredMessage() {
        seedValid()
        fake.refreshHandler = { _, _ -> throw RefreshRejectedException() }
        composeTestRule.setContent {
            SamvaadTheme {
                SessionGate(
                    authApi = fake,
                    sessionStore = store,
                    refresher = SessionRefresher(fake, store),
                )
            }
        }
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Server address").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        composeTestRule.onNodeWithText("Your session has expired. Please sign in again.")
            .performScrollTo()
        composeTestRule.onNodeWithText("Your session has expired. Please sign in again.")
            .assertIsDisplayed()
    }

    @Test
    fun restore_noRecord_showsBareLogin() {
        composeTestRule.setContent {
            SamvaadTheme {
                SessionGate(
                    authApi = fake,
                    sessionStore = store,
                    refresher = SessionRefresher(fake, store),
                )
            }
        }
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Server address").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        // No expired-session notice on a clean first launch.
        composeTestRule.onNodeWithText("Your session has expired. Please sign in again.")
            .assertDoesNotExist()
    }

    @Test
    fun login_persistsBundle_beforeHome() {
        fake.loginResult = Result.success(
            AuthSession("alice", "access-1", "refresh-1", "11111111-2222-3333-4444-555555555555")
        )
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadEntryScreen(authApi = fake, sessionStore = store)
            }
        }
        composeTestRule.onNodeWithText("Server address").performTextInput("https://example.test:8080/")
        composeTestRule.onNodeWithText("Username").performTextInput("alice")
        composeTestRule.onNodeWithText("Password").performTextInput("s3cr3t!")
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Signed in as alice").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        val loaded = store.load()!!
        assertEquals("https://example.test:8080", loaded.serverAddress)
        assertEquals("alice", loaded.identifier)
        assertEquals("refresh-1", loaded.refreshToken)
        assertEquals("11111111-2222-3333-4444-555555555555", loaded.sessionId)
    }

    @Test
    fun login_storeFailure_stillEntersHome() {
        fake.loginResult = Result.success(
            AuthSession("alice", "access-1", "refresh-1", "11111111-2222-3333-4444-555555555555")
        )
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadEntryScreen(authApi = fake, sessionStore = ThrowingStore(store))
            }
        }
        composeTestRule.onNodeWithText("Server address").performTextInput("https://example.test:8080/")
        composeTestRule.onNodeWithText("Username").performTextInput("alice")
        composeTestRule.onNodeWithText("Password").performTextInput("s3cr3t!")
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Signed in as alice").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        // Durability unavailable: live session works, nothing persisted.
        assertNull(store.load())
    }

    @Test
    fun logout_returnsToEntry_andWipesSessionOnly() {
        seedValid()
        fake.refreshHandler = { _, _ ->
            RefreshedSession("access-2", "refresh-2", "11111111-2222-3333-4444-555555555555")
        }
        var logoutCalls = 0
        fake.logoutHandler = { _, _ -> logoutCalls++ }
        composeTestRule.setContent {
            SamvaadTheme {
                SessionGate(
                    authApi = fake,
                    sessionStore = store,
                    refresher = SessionRefresher(fake, store),
                )
            }
        }
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Log out").fetchSemanticsNode()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        composeTestRule.onNodeWithText("Log out").performScrollTo()
        composeTestRule.onNodeWithText("Log out").performClick()
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Server address").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        assertEquals(1, logoutCalls)
        assertNull(store.load())
    }

    @Test
    fun restoring_indicator_shownDuringSlowRefresh() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        // Seed first so the gate attempts a refresh (and blocks on it).
        seedValid()
        fake.refreshHandler = { _, _ ->
            entered.countDown()
            withContext(Dispatchers.IO) {
                assertTrue(release.await(10, TimeUnit.SECONDS))
            }
            RefreshedSession("access-2", "refresh-2", "11111111-2222-3333-4444-555555555555")
        }
        composeTestRule.setContent {
            SamvaadTheme {
                SessionGate(
                    authApi = fake,
                    sessionStore = store,
                    refresher = SessionRefresher(fake, store),
                )
            }
        }
        // The restoring indicator must be visible while blocked.
        composeTestRule.waitUntil(10_000) {
            try {
                composeTestRule.onNodeWithText("Restoring session…").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
        release.countDown()
        composeTestRule.waitUntil(30_000) {
            try {
                composeTestRule.onNodeWithText("Signed in as alice").assertExists()
                true
            } catch (_: AssertionError) {
                false
            }
        }
    }
}
