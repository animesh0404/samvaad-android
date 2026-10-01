package com.samvaad.android

import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.IOException
import java.util.concurrent.CountDownLatch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice 1–2 entry/auth tests. Host-side via Robolectric; HTTP is faked —
 * no live server required.
 */
@RunWith(RobolectricTestRunner::class)
// Slice 1: pinned to SDK 36. The Compose BOM's espresso-idling-resource
// calls the hidden InputManager.getInstance(), which no longer exists in
// Robolectric's SDK 37 runtime jar.
@Config(sdk = [36])
class EntryScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private class FakeAuthApi : AuthApi {
        val calls = mutableListOf<LoginRequest>()
        var result: Result<AuthSession> = Result.success(
            AuthSession(
                identifier = "alice",
                accessToken = "access-1",
                refreshToken = "refresh-1",
                sessionId = "session-1",
            )
        )
        var gate: CountDownLatch? = null

        override suspend fun login(request: LoginRequest): AuthSession {
            calls += request
            withContext(Dispatchers.IO) {
                gate?.await()
            }
            return result.getOrThrow()
        }
    }

    private fun setEntryContent(fake: FakeAuthApi = FakeAuthApi()) {
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadEntryScreen(authApi = fake)
            }
        }
    }

    private fun fillValidForm() {
        composeTestRule
            .onNodeWithText("Server address")
            .performTextInput("https://samvaad.example:8080/")
        composeTestRule
            .onNodeWithText("Username")
            .performTextInput("alice")
        composeTestRule
            .onNodeWithText("Password")
            .performTextInput("s3cr3t!")
    }

    @Test
    fun branding_isDisplayed() {
        setEntryContent()

        composeTestRule.onNodeWithText("Samvaad").assertIsDisplayed()
        composeTestRule
            .onNodeWithContentDescription("Samvaad logo")
            .assertIsDisplayed()
    }

    @Test
    fun entryFields_exist() {
        setEntryContent()

        composeTestRule.onNodeWithText("Server address").assertIsDisplayed()
        composeTestRule.onNodeWithText("Username").assertIsDisplayed()
        composeTestRule.onNodeWithText("Password").assertIsDisplayed()
    }

    @Test
    fun entryFields_acceptText() {
        setEntryContent()

        composeTestRule
            .onNodeWithText("Server address")
            .performTextInput("https://samvaad.example:8080")
        composeTestRule
            .onNodeWithText("Username")
            .performTextInput("alice")

        composeTestRule
            .onNodeWithText("https://samvaad.example:8080")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("alice").assertIsDisplayed()
    }

    @Test
    fun emptySubmission_issuesNoLoginRequest() {
        val fake = FakeAuthApi()
        setEntryContent(fake)

        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        assert(fake.calls.isEmpty())
        composeTestRule
            .onNodeWithText("Enter a server address, username, and password.")
            .performScrollTo()
        composeTestRule
            .onNodeWithText("Enter a server address, username, and password.")
            .assertIsDisplayed()
    }

    @Test
    fun invalidServerAddress_issuesNoLoginRequest() {
        val fake = FakeAuthApi()
        setEntryContent(fake)

        composeTestRule
            .onNodeWithText("Server address")
            .performTextInput("not a url")
        composeTestRule
            .onNodeWithText("Username")
            .performTextInput("alice")
        composeTestRule
            .onNodeWithText("Password")
            .performTextInput("s3cr3t!")
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        assert(fake.calls.isEmpty())
        composeTestRule
            .onNodeWithText("Enter a valid server address, e.g. https://host:8080.")
            .performScrollTo()
        composeTestRule
            .onNodeWithText("Enter a valid server address, e.g. https://host:8080.")
            .assertIsDisplayed()
    }

    @Test
    fun loginRequest_usesConfiguredAddressIdentifierPasswordAndAndroidPlatform() {
        val fake = FakeAuthApi()
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        composeTestRule.waitForIdle()
        assert(fake.calls.size == 1)
        val request = fake.calls.single()
        assert(request.serverAddress == "https://samvaad.example:8080")
        assert(request.identifier == "alice")
        assert(request.password == "s3cr3t!")
        assert(request.clientPlatform == "ANDROID")
    }

    @Test
    fun successfulLogin_showsAuthenticatedStateWithoutSecrets() {
        val fake = FakeAuthApi()
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        composeTestRule
            .onNodeWithText("Signed in as alice")
            .performScrollTo()
        composeTestRule.onNodeWithText("Signed in as alice").assertIsDisplayed()
        composeTestRule
            .onAllNodesWithText("access-1", substring = true)
            .assertCountEquals(0)
        composeTestRule
            .onAllNodesWithText("refresh-1", substring = true)
            .assertCountEquals(0)
        composeTestRule
            .onAllNodesWithText("session-1", substring = true)
            .assertCountEquals(0)
        composeTestRule
            .onAllNodesWithText("s3cr3t!", substring = true)
            .assertCountEquals(0)
    }

    @Test
    fun rejectedLogin_showsSafeErrorWithoutInternals() {
        val fake = FakeAuthApi()
        fake.result = Result.failure(AuthRejectedException())
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        composeTestRule
            .onNodeWithText("Sign in failed. Check your details and try again.")
            .performScrollTo()
        composeTestRule
            .onNodeWithText("Sign in failed. Check your details and try again.")
            .assertIsDisplayed()
        composeTestRule
            .onAllNodesWithText("AuthRejected", substring = true)
            .assertCountEquals(0)
    }

    @Test
    fun unreachableServer_showsSafeErrorWithoutInternals() {
        val fake = FakeAuthApi()
        fake.result = Result.failure(IOException("connection refused"))
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        composeTestRule
            .onNodeWithText("Cannot reach the server. Check the address and try again.")
            .performScrollTo()
        composeTestRule
            .onNodeWithText("Cannot reach the server. Check the address and try again.")
            .assertIsDisplayed()
        composeTestRule
            .onAllNodesWithText("connection refused", substring = true)
            .assertCountEquals(0)
    }

    @Test
    fun duplicateSubmissionWhileInFlight_issuesSingleLoginRequest() {
        val fake = FakeAuthApi()
        fake.gate = CountDownLatch(1)
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()
        composeTestRule.onNodeWithText("Continue").performClick()

        fake.gate!!.countDown()
        composeTestRule.waitForIdle()
        assert(fake.calls.size == 1)
        composeTestRule
            .onNodeWithText("Signed in as alice")
            .performScrollTo()
        composeTestRule.onNodeWithText("Signed in as alice").assertIsDisplayed()
    }
}
